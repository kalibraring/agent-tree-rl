from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time
import unittest
from unittest.mock import patch

from agent_tree_rl.api import ProductionHTTPServer, RequestHandler
from agent_tree_rl.config import Settings
from agent_tree_rl.metrics import Metrics
from agent_tree_rl.process_registry import (
    ActiveProcessRegistry,
    ProcessRegistryClosed,
)
from agent_tree_rl.store import ConflictError, SQLiteStore, StoreError


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ProcessRegistryTests(unittest.TestCase):
    def test_cancellation_during_spawn_kills_late_child_before_registration(
        self,
    ) -> None:
        registry = ActiveProcessRegistry()

        class FakeProcess:
            pid = 987_654
            returncode: int | None = None
            waited = False

            def wait(self, timeout: float) -> int:
                del timeout
                self.waited = True
                self.returncode = -signal.SIGKILL
                return self.returncode

        process = FakeProcess()

        def spawn_during_signal(*_args: object, **_kwargs: object) -> FakeProcess:
            registry.cancel_all(timeout_seconds=0.1)
            return process

        with (
            patch(
                "agent_tree_rl.process_registry.subprocess.Popen",
                side_effect=spawn_during_signal,
            ),
            patch.object(registry, "_signal") as send_signal,
        ):
            with self.assertRaises(ProcessRegistryClosed):
                registry.spawn(["late-child"])
        self.assertTrue(process.waited)
        self.assertEqual(signal.SIGKILL, send_signal.call_args.args[1])


class StartupRecoveryTests(unittest.TestCase):
    def test_recovery_preserves_already_expired_ambiguous_key_as_tombstone(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "aged.sqlite3"
            with SQLiteStore(database, clock=lambda: 1_000.0) as crashed:
                crashed.claim_idempotency(
                    "tenant",
                    "evidence",
                    "expired-interrupted-key",
                    {"command": "effect"},
                    ttl_seconds=5,
                )

            # Service startup reconciles before accepting/claiming work, even
            # when the ordinary 24-hour-style TTL elapsed during the outage.
            with SQLiteStore(database, clock=lambda: 2_000.0) as recovered:
                report = recovered.reconcile_startup()
                self.assertEqual(1, report["failed_idempotency_records"])
                tombstone = recovered.claim_idempotency(
                    "tenant",
                    "evidence",
                    "expired-interrupted-key",
                    {"command": "effect"},
                )
                self.assertEqual("FAILED", tombstone.status)
                self.assertFalse(tombstone.is_new)
                self.assertIsNone(tombstone.expires_at)

    def test_recovery_aborts_without_mutation_on_budget_accounting_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with SQLiteStore(Path(directory) / "mismatch.sqlite3") as store:
                store.claim_idempotency(
                    "tenant", "decision", "interrupted-key", {"units": 5}
                )
                store.create_budget("tenant", "api-compute", 20)
                store.reserve_budget(
                    "tenant", "api-compute", "interrupted-reservation", 5
                )
                # Fault injection represents a damaged/restored database. The
                # public recovery boundary must refuse to guess at capacity.
                with store.transaction() as connection:
                    connection.execute(
                        "UPDATE budgets SET reserved_units=6 "
                        "WHERE tenant_id='tenant' AND budget_id='api-compute'"
                    )

                with self.assertRaisesRegex(StoreError, "accounting mismatch"):
                    store.reconcile_startup()
                record = store.claim_idempotency(
                    "tenant", "decision", "interrupted-key", {"units": 5}
                )
                self.assertEqual("IN_PROGRESS", record.status)
                self.assertEqual(
                    6,
                    store.get_budget("tenant", "api-compute").reserved_units,
                )

    def test_sigkill_recovery_fails_interrupted_key_closed_and_releases_only_reserved_budget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "recovery.sqlite3"
            crash_script = """
import os
from pathlib import Path
import signal
import sys
from agent_tree_rl.store import SQLiteStore

store = SQLiteStore(Path(sys.argv[1]))
store.claim_idempotency("tenant", "decision", "interrupted-key", {"units": 7})
store.create_budget("tenant", "api-compute", 20)
store.reserve_budget("tenant", "api-compute", "interrupted-reservation", 7)
store.acquire_lease("tenant", "train:policy", "dead-worker", ttl_seconds=3600)
os.kill(os.getpid(), signal.SIGKILL)
"""
            crashed = subprocess.run(
                [sys.executable, "-c", crash_script, str(database)],
                cwd=PROJECT_ROOT,
                check=False,
            )
            self.assertEqual(-signal.SIGKILL, crashed.returncode)

            with SQLiteStore(database) as recovered:
                # Opening the store for backup, doctor, or inspection is
                # non-mutating; only service startup invokes reconciliation.
                before = recovered.claim_idempotency(
                    "tenant", "decision", "interrupted-key", {"units": 7}
                )
                self.assertEqual("IN_PROGRESS", before.status)
                self.assertEqual(
                    7,
                    recovered.get_budget(
                        "tenant", "api-compute"
                    ).reserved_units,
                )
                report = recovered.reconcile_startup()
                self.assertEqual(
                    {
                        "failed_idempotency_records": 1,
                        "released_budget_reservations": 1,
                        "released_budget_units": 7,
                        "released_leases": 1,
                    },
                    report,
                )
                interrupted = recovered.claim_idempotency(
                    "tenant", "decision", "interrupted-key", {"units": 7}
                )
                self.assertEqual("FAILED", interrupted.status)
                self.assertEqual(
                    {
                        "error_type": "InterruptedOperation",
                        "retry_safe": False,
                    },
                    interrupted.result,
                )
                self.assertIsNone(interrupted.expires_at)
                budget = recovered.get_budget("tenant", "api-compute")
                self.assertEqual((0, 0, 20), (
                    budget.reserved_units,
                    budget.consumed_units,
                    budget.available_units,
                ))
                self.assertIsNone(
                    recovered.get_lease("tenant", "train:policy").holder_id
                )

                # A caller must use a new key after investigating external effects.
                recovered.claim_idempotency(
                    "tenant", "decision", "replacement-key", {"units": 7}
                )
                recovered.reserve_budget(
                    "tenant", "api-compute", "replacement-reservation", 7
                )
                with recovered.transaction():
                    recovered.consume_budget(
                        "tenant", "api-compute", "replacement-reservation"
                    )
                    recovered.complete_idempotency(
                        "tenant", "decision", "replacement-key", {"committed": True}
                    )

                self.assertEqual(
                    {
                        "failed_idempotency_records": 0,
                        "released_budget_reservations": 0,
                        "released_budget_units": 0,
                        "released_leases": 0,
                    },
                    recovered.reconcile_startup(),
                )
                budget = recovered.get_budget("tenant", "api-compute")
                self.assertEqual((0, 7, 13), (
                    budget.reserved_units,
                    budget.consumed_units,
                    budget.available_units,
                ))
                with self.assertRaises(ConflictError):
                    recovered.fail_idempotency(
                        "tenant", "decision", "replacement-key", {"late": True}
                    )

            with SQLiteStore(
                database,
                clock=lambda: time.time() + 10 * 86_400,
            ) as aged:
                tombstone = aged.claim_idempotency(
                    "tenant", "decision", "interrupted-key", {"units": 7}
                )
                self.assertEqual("FAILED", tombstone.status)
                self.assertFalse(tombstone.is_new)
                self.assertIsNone(tombstone.expires_at)


class _BlockingControl:
    def __init__(self) -> None:
        self.work_started = Event()
        self.release_work = Event()
        self.health_started = Event()
        self.release_health = Event()
        self.block_health = False
        self.draining = False
        self.block_drain = False
        self.drain_started = Event()
        self.release_drain = Event()

    def begin_draining(self) -> bool:
        if self.block_drain:
            self.drain_started.set()
            self.release_drain.wait(timeout=5)
        changed = not self.draining
        self.draining = True
        return changed

    def health(self) -> dict[str, object]:
        if self.block_health:
            self.health_started.set()
            self.release_health.wait(timeout=5)
        return {"status": "draining" if self.draining else "ok"}

    def readiness(self) -> dict[str, object]:
        return {
            "ready": not self.draining,
            "lifecycle": "draining" if self.draining else "ready",
        }

    def run_decision(
        self, principal: object, body: dict[str, object], *, idempotency_key: str
    ) -> dict[str, object]:
        del principal, body, idempotency_key
        self.work_started.set()
        self.release_work.wait(timeout=5)
        return {"completed": True}


class HTTPDrainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.settings = Settings(
            host="127.0.0.1",
            port=0,
            data_dir=root,
            database_path=root / "unused.sqlite3",
            receipt_keys_file=root / "unused-keys.json",
            admin_token_file=root / "unused-tokens.json",
            benchmark_dir=root,
            require_auth=False,
            max_workers=1,
            max_operational_workers=1,
        )
        self.control = _BlockingControl()
        self.server = ProductionHTTPServer(
            ("127.0.0.1", 0),
            RequestHandler,
            settings=self.settings,
            control=self.control,
            metrics=Metrics(),
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.control.release_work.set()
        self.control.release_health.set()
        self.control.release_drain.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def _request(
        self,
        method: str,
        path: str,
        *,
        key: str = "lifecycle-key-0001",
    ) -> tuple[int, dict[str, object] | str]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=5
        )
        body = b"{}" if method == "POST" else None
        headers: dict[str, str] = {}
        if body is not None:
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": key,
            }
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        if response.getheader("Content-Type", "").startswith("application/json"):
            return response.status, json.loads(raw)
        return response.status, raw.decode()

    def test_work_saturation_does_not_starve_probes_and_drain_rejects_new_work(
        self,
    ) -> None:
        first_result: list[tuple[int, dict[str, object] | str]] = []
        first = Thread(target=lambda: first_result.append(self._request(
            "POST", "/v1/decisions/run", key="first-work-key"
        )))
        first.start()
        self.assertTrue(self.control.work_started.wait(timeout=2))

        overloaded_status, overloaded = self._request(
            "POST", "/v1/decisions/run", key="second-work-key"
        )
        self.assertEqual(503, overloaded_status)
        self.assertEqual("overloaded", overloaded["error"]["code"])
        self.assertEqual(200, self._request("GET", "/healthz")[0])

        self.assertTrue(self.server.begin_draining())
        self.assertFalse(self.server.begin_draining())
        ready_status, ready = self._request("GET", "/readyz")
        self.assertEqual(503, ready_status)
        self.assertEqual("draining", ready["lifecycle"])
        draining_status, draining = self._request(
            "POST", "/v1/decisions/run", key="draining-work-key"
        )
        self.assertEqual(503, draining_status)
        self.assertEqual("draining", draining["error"]["code"])
        self.assertFalse(self.server.wait_for_drain(timeout=0.01))

        self.control.release_work.set()
        first.join(timeout=2)
        self.assertFalse(first.is_alive())
        self.assertEqual(200, first_result[0][0])
        self.assertTrue(self.server.wait_for_drain(timeout=1))

    def test_readiness_and_work_admission_cross_the_drain_gate_atomically(
        self,
    ) -> None:
        self.control.block_drain = True
        drain = Thread(target=self.server.begin_draining)
        drain.start()
        self.assertTrue(self.control.drain_started.wait(timeout=2))

        admission: list[str | None] = []
        contender = Thread(
            target=lambda: admission.append(
                self.server.admit_request(operational=False)
            )
        )
        contender.start()
        contender.join(timeout=0.05)
        self.assertTrue(contender.is_alive())

        self.control.release_drain.set()
        drain.join(timeout=2)
        contender.join(timeout=2)
        self.assertEqual(["draining"], admission)
        self.assertEqual("draining", self.control.readiness()["lifecycle"])

    def test_operational_capacity_is_separately_bounded(self) -> None:
        self.control.block_health = True
        first_result: list[tuple[int, dict[str, object] | str]] = []
        first = Thread(
            target=lambda: first_result.append(self._request("GET", "/healthz"))
        )
        first.start()
        self.assertTrue(self.control.health_started.wait(timeout=2))
        self.server.begin_draining()
        self.assertTrue(self.server.wait_for_drain(timeout=0.01))

        status, payload = self._request("GET", "/readyz")
        self.assertEqual(503, status)
        self.assertEqual("operational_overloaded", payload["error"]["code"])

        self.control.release_health.set()
        first.join(timeout=2)
        self.assertEqual(200, first_result[0][0])


class CLISignalIntegrationTests(unittest.TestCase):
    @staticmethod
    def _free_port() -> int:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def _wait_until_serving(self, process: subprocess.Popen[str], port: int) -> None:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(
                    f"service exited before health check: {process.returncode}\n"
                    f"stdout={stdout}\nstderr={stderr}"
                )
            try:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", port, timeout=0.25
                )
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                response.read()
                connection.close()
                if response.status == 200:
                    return
            except OSError:
                time.sleep(0.05)
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        self.fail(f"service did not start\nstdout={stdout}\nstderr={stderr}")

    @staticmethod
    def _sleep_children(parent_pid: int) -> list[int]:
        listing = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,command="],
            text=True,
        )
        result: list[int] = []
        for line in listing.splitlines():
            fields = line.strip().split(None, 2)
            if (
                len(fields) == 3
                and int(fields[1]) == parent_pid
                and "/bin/sleep 60" in fields[2]
            ):
                result.append(int(fields[0]))
        return result

    def test_sigterm_drains_closes_and_allows_clean_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "data"
            initialized = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_tree_rl.cli",
                    "init",
                    "--data-dir",
                    str(data_dir),
                    "--tenant",
                    "lifecycle-test",
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, initialized.returncode, initialized.stderr)
            initialization = json.loads(initialized.stdout)
            token_output = Path(initialization["token_output"])
            self.assertEqual(0o600, stat.S_IMODE(token_output.stat().st_mode))
            plaintext_tokens = json.loads(token_output.read_text(encoding="utf-8"))
            operator_token = plaintext_tokens["api_tokens"]["operator"]
            self.assertNotIn(operator_token, initialized.stdout)

            environment = os.environ.copy()
            environment.update(
                {
                    "AGENT_TREE_RL_DATA_DIR": str(data_dir),
                    "AGENT_TREE_RL_HOST": "127.0.0.1",
                    "AGENT_TREE_RL_ALLOW_SAMPLE_BENCHMARK": "true",
                    "AGENT_TREE_RL_ALLOWED_COMMANDS": "/bin/sleep",
                    "AGENT_TREE_RL_ALLOWED_CWD_ROOTS": str(PROJECT_ROOT),
                    "AGENT_TREE_RL_SHUTDOWN_GRACE_SECONDS": "3",
                    "AGENT_TREE_RL_SHUTDOWN_CANCEL_SECONDS": "3",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )

            for attempt in range(2):
                port = self._free_port()
                environment["AGENT_TREE_RL_PORT"] = str(port)
                process = subprocess.Popen(
                    [sys.executable, "-m", "agent_tree_rl.cli", "serve"],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self._wait_until_serving(process, port)
                if attempt == 0:
                    contender_environment = dict(environment)
                    contender_environment["AGENT_TREE_RL_PORT"] = str(
                        self._free_port()
                    )
                    contender = subprocess.run(
                        [sys.executable, "-m", "agent_tree_rl.cli", "serve"],
                        cwd=PROJECT_ROOT,
                        env=contender_environment,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    self.assertEqual(1, contender.returncode)
                    self.assertIn("already in use", contender.stderr)
                child_pids: list[int] = []
                evidence_thread: Thread | None = None
                if attempt == 0:
                    evidence_result: list[object] = []

                    def run_long_evidence() -> None:
                        try:
                            connection = http.client.HTTPConnection(
                                "127.0.0.1", port, timeout=10
                            )
                            body = json.dumps(
                                {
                                    "command_id": "cmd0",
                                    "arguments": ["60"],
                                    "cwd": str(PROJECT_ROOT),
                                }
                            ).encode()
                            connection.request(
                                "POST",
                                "/v1/evidence/run",
                                body=body,
                                headers={
                                    "Authorization": f"Bearer {operator_token}",
                                    "Content-Type": "application/json",
                                    "Content-Length": str(len(body)),
                                    "Idempotency-Key": "long-evidence-key-0001",  # gitleaks:allow
                                },
                            )
                            response = connection.getresponse()
                            evidence_result.append((response.status, response.read()))
                            connection.close()
                        except OSError as error:
                            evidence_result.append(error)

                    evidence_thread = Thread(target=run_long_evidence)
                    evidence_thread.start()
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not child_pids:
                        child_pids = self._sleep_children(process.pid)
                        if not child_pids:
                            time.sleep(0.05)
                    self.assertEqual(1, len(child_pids), evidence_result)
                process.send_signal(signal.SIGTERM)
                try:
                    return_code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=5)
                    self.fail(
                        f"service ignored SIGTERM\nstdout={stdout}\nstderr={stderr}"
                    )
                stdout, stderr = process.communicate()
                self.assertEqual(
                    1 if attempt == 0 else 0,
                    return_code,
                    f"stdout={stdout}\nstderr={stderr}",
                )
                if evidence_thread is not None:
                    evidence_thread.join(timeout=5)
                    self.assertFalse(evidence_thread.is_alive())
                for child_pid in child_pids:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)

            # A normal store open remains possible after the service releases
            # both its socket and exclusive runtime lock.
            with SQLiteStore(data_dir / "agent-tree-rl.sqlite3") as store:
                self.assertEqual(("ok",), store.integrity_check())


if __name__ == "__main__":
    unittest.main()
