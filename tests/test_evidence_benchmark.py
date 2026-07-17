from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from threading import Thread
import time
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_tree_rl.crypto import (  # noqa: E402
    InvalidSignatureError,
    ReceiptSigner,
    ReceiptVerifier,
)
from agent_tree_rl.evidence import (  # noqa: E402
    EvidenceRunner,
    PolicyViolation,
    RunnerPolicy,
    canonical_json,
    load_hmac_key,
)
from agent_tree_rl.hidden_benchmark import (  # noqa: E402
    BenchmarkProtocolError,
    BenchmarkSchemaError,
    BenchmarkSecurityError,
    HiddenBenchmarkClient,
    HiddenBenchmarkConfig,
    candidate_fingerprint,
    load_private_benchmark_for_worker,
    opaque_suite_digest,
    strict_json_loads,
    validate_aggregate_receipt,
)
from agent_tree_rl.process_registry import ActiveProcessRegistry  # noqa: E402


KEY_ID = "test-key-v1"
KEY = b"evidence-test-key-material-is-at-least-32-bytes"


class EvidenceRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.signer = ReceiptSigner({KEY_ID: KEY}, KEY_ID)
        self.verifier = ReceiptVerifier({KEY_ID: KEY}, clock_skew_seconds=60)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def runner(
        self,
        *,
        timeout: float = 2.0,
        cap: int = 32 * 1024,
        allowed_environment: frozenset[str] = frozenset(),
        artifact_file_cap: int = 64 * 1024 * 1024,
        artifact_total_cap: int = 256 * 1024 * 1024,
        artifact_timeout: float = 10.0,
    ) -> EvidenceRunner:
        policy = RunnerPolicy(
            allowed_executables={"python": Path(sys.executable).resolve()},
            allowed_cwd_roots=(self.root,),
            timeout_seconds=timeout,
            output_cap_bytes=cap,
            allowed_environment=allowed_environment,
            artifact_file_cap_bytes=artifact_file_cap,
            artifact_total_cap_bytes=artifact_total_cap,
            artifact_hash_timeout_seconds=artifact_timeout,
        )
        return EvidenceRunner(policy, self.signer, tenant_id="tenant-a")

    def payload(self, result: object) -> dict[str, object]:
        receipt = result.receipt  # type: ignore[attr-defined]
        value = self.verifier.verify(
            receipt,
            expected_purpose="subprocess-evidence",
            expected_tenant_id="tenant-a",
        )
        self.assertIsInstance(value, dict)
        return value  # type: ignore[return-value]

    def test_exact_executable_sanitized_environment_and_no_shell(self) -> None:
        script = (
            "import json,os,sys;"
            "print(json.dumps({'env':dict(os.environ),'arg':sys.argv[1]},sort_keys=True))"
        )
        result = self.runner(allowed_environment=frozenset({"VISIBLE"})).run(
            ["python", "-c", script, "$HOME;echo injected"],
            cwd=self.root,
            env={"VISIBLE": "yes"},
        )
        self.assertTrue(result.ok)
        output = json.loads(result.stdout)
        self.assertEqual(output["arg"], "$HOME;echo injected")
        # macOS may inject __CF_USER_TEXT_ENCODING after exec; inherited
        # controller secrets such as HOME/PATH must still be absent.
        self.assertEqual(output["env"]["LANG"], "C")
        self.assertEqual(output["env"]["LC_ALL"], "C")
        self.assertEqual(output["env"]["TZ"], "UTC")
        self.assertEqual(output["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(output["env"]["VISIBLE"], "yes")
        self.assertNotIn("HOME", output["env"])
        self.assertNotIn("PATH", output["env"])
        payload = self.payload(result)
        self.assertFalse(payload["command"]["shell"])  # type: ignore[index]
        self.assertEqual(payload["outcome"], "passed")

    def test_rejects_path_lookup_unlisted_env_and_outside_cwd(self) -> None:
        runner = self.runner()
        with self.assertRaises(PolicyViolation):
            runner.run(["python3", "-V"], cwd=self.root)
        with self.assertRaises(PolicyViolation):
            runner.run(["python", "-V"], cwd=self.root, env={"HOME": "/tmp"})
        with self.assertRaises(PolicyViolation):
            runner.run(["python", "-V"], cwd=self.root.parent)

        disguised = self.root / "safe-probe"
        disguised.symlink_to(Path(sys.executable).resolve())
        with self.assertRaisesRegex(PolicyViolation, "symlink"):
            EvidenceRunner(
                RunnerPolicy(
                    allowed_executables={"probe": disguised},
                    allowed_cwd_roots=(self.root,),
                ),
                self.signer,
                tenant_id="tenant-a",
            )

    def test_timeout_kills_process_group_and_is_attested(self) -> None:
        result = self.runner(timeout=0.08).run(
            ["python", "-c", "import time;time.sleep(5)"], cwd=self.root
        )
        payload = self.payload(result)
        self.assertEqual(payload["outcome"], "timeout")
        self.assertEqual(payload["process"]["termination"], "timeout")  # type: ignore[index]

    def test_output_cap_kills_infinite_or_excessive_writer(self) -> None:
        result = self.runner(cap=1024).run(
            ["python", "-c", "import os;os.write(1,b'x'*200000)"], cwd=self.root
        )
        payload = self.payload(result)
        self.assertEqual(payload["outcome"], "output_limit")
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 1024)
        self.assertTrue(payload["output"]["truncated"])  # type: ignore[index]

    def test_artifact_digest_stdin_digest_and_host_fingerprints(self) -> None:
        result = self.runner().run(
            [
                "python",
                "-c",
                "import pathlib,sys;pathlib.Path('proof.bin').write_bytes(sys.stdin.buffer.read())",
            ],
            cwd=self.root,
            stdin=b"proof-data",
            artifacts=("proof.bin",),
        )
        payload = self.payload(result)
        self.assertTrue(result.ok)
        artifact = payload["artifacts"][0]  # type: ignore[index]
        self.assertEqual(artifact["status"], "hashed")
        self.assertEqual(artifact["sha256"], __import__("hashlib").sha256(b"proof-data").hexdigest())
        self.assertEqual(payload["input"]["size_bytes"], 10)  # type: ignore[index]
        self.assertRegex(payload["fingerprints"]["host_sha256"], r"^[0-9a-f]{64}$")  # type: ignore[index]

    def test_missing_or_symlink_artifact_fails_closed(self) -> None:
        missing = self.runner().run(
            ["python", "-c", "pass"], cwd=self.root, artifacts=("missing.bin",)
        )
        self.assertEqual(self.payload(missing)["outcome"], "artifact_error")
        target = self.root / "target.bin"
        target.write_bytes(b"x")
        link = self.root / "link.bin"
        link.symlink_to(target)
        linked = self.runner().run(
            ["python", "-c", "pass"], cwd=self.root, artifacts=(link,)
        )
        self.assertEqual(self.payload(linked)["outcome"], "artifact_error")

    def test_artifact_file_and_aggregate_caps_fail_boundedly(self) -> None:
        sparse = self.root / "sparse.bin"
        with sparse.open("wb") as handle:
            handle.truncate(2048)
        oversized = self.runner(
            artifact_file_cap=1024,
            artifact_total_cap=2048,
        ).run(["python", "-c", "pass"], cwd=self.root, artifacts=(sparse,))
        oversized_payload = self.payload(oversized)
        self.assertEqual("artifact_error", oversized_payload["outcome"])
        self.assertEqual("size_limit", oversized_payload["artifacts"][0]["status"])

        first = self.root / "first.bin"
        second = self.root / "second.bin"
        first.write_bytes(b"a" * 800)
        second.write_bytes(b"b" * 800)
        aggregate = self.runner(
            artifact_file_cap=1024,
            artifact_total_cap=1200,
        ).run(
            ["python", "-c", "pass"],
            cwd=self.root,
            artifacts=(first, second),
        )
        aggregate_payload = self.payload(aggregate)
        self.assertEqual("artifact_error", aggregate_payload["outcome"])
        self.assertEqual(
            "aggregate_size_limit",
            aggregate_payload["artifacts"][1]["status"],
        )

    def test_artifact_hash_deadline_and_in_place_change_fail_closed(self) -> None:
        artifact = self.root / "changing.bin"
        artifact.write_bytes(b"a" * (2 * 1024 * 1024))
        timed_out = EvidenceRunner._hash_artifact(
            artifact,
            max_bytes=4 * 1024 * 1024,
            deadline=time.monotonic() - 1,
        )
        self.assertEqual("hash_timeout", timed_out["status"])

        real_read = os.read
        changed = False

        def mutate_after_read(descriptor: int, size: int) -> bytes:
            nonlocal changed
            chunk = real_read(descriptor, size)
            if chunk and not changed:
                changed = True
                with artifact.open("r+b") as handle:
                    handle.seek(0)
                    handle.write(b"b")
                    handle.flush()
                    os.fsync(handle.fileno())
            return chunk

        with patch(
            "agent_tree_rl.evidence.os.read",
            side_effect=mutate_after_read,
        ):
            result = EvidenceRunner._hash_artifact(
                artifact,
                max_bytes=4 * 1024 * 1024,
            )
        self.assertEqual("changed_while_hashing", result["status"])

    def test_receipt_tampering_is_rejected_by_shared_verifier(self) -> None:
        result = self.runner().run(["python", "-c", "pass"], cwd=self.root)
        altered = copy.deepcopy(result.receipt)
        altered["payload"]["outcome"] = "passed-by-attacker"
        with self.assertRaises(InvalidSignatureError):
            self.verifier.verify(altered)

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits required")
    def test_hmac_key_requires_owner_only_permissions(self) -> None:
        key = self.root / "key.bin"
        key.write_bytes(KEY)
        key.chmod(0o644)
        with self.assertRaises(PolicyViolation):
            load_hmac_key(key)
        key.chmod(0o600)
        self.assertEqual(load_hmac_key(key), KEY)


class HiddenBenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.worker = PROJECT_ROOT / "agent_tree_rl/workers/benchmark_worker.py"
        self.key_file = self.root / "benchmark.key"
        self.key_file.write_bytes(KEY)
        self.key_file.chmod(0o600)
        self.signer = ReceiptSigner({KEY_ID: KEY}, KEY_ID)
        self.verifier = ReceiptVerifier({KEY_ID: KEY}, clock_skew_seconds=60)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_suite(self, cases: list[dict[str, object]]) -> Path:
        suite = self.root / "private.json"
        suite.write_bytes(
            canonical_json(
                {
                    "schema_version": 1,
                    "benchmark_id": "hidden-test-v1",
                    "cases": cases,
                }
            )
        )
        suite.chmod(0o600)
        return suite

    def write_candidate(self, source: str) -> Path:
        candidate = self.root / "candidate.py"
        candidate.write_text(source, encoding="utf-8")
        return candidate

    def client(
        self,
        suite: Path,
        *,
        process_registry: ActiveProcessRegistry | None = None,
        case_timeout_seconds: float = 1.0,
    ) -> HiddenBenchmarkClient:
        return HiddenBenchmarkClient(
            HiddenBenchmarkConfig(
                worker_script=self.worker,
                benchmark_path=suite,
                signing_key_path=self.key_file,
                key_id=KEY_ID,
                candidate_executables=(Path(sys.executable).resolve(),),
                candidate_cwd_roots=(self.root,),
                case_timeout_seconds=case_timeout_seconds,
                candidate_output_cap_bytes=4096,
                worker_timeout_seconds=10.0,
                worker_tenant_id="benchmark-service",
            ),
            self.verifier,
            process_registry=process_registry,
        )

    def test_service_cancellation_reaps_sigterm_ignoring_nested_candidate(
        self,
    ) -> None:
        suite = self.write_suite(
            [{"id": "slow", "input": 1, "expected": 1, "weight_micros": 1}]
        )
        candidate = self.write_candidate(
            "import os,pathlib,signal,time\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path('candidate.pid').write_text(str(os.getpid()))\n"
            "time.sleep(60)\n"
        )
        registry = ActiveProcessRegistry()
        client = self.client(
            suite,
            process_registry=registry,
            case_timeout_seconds=60,
        )
        outcome: list[BaseException | object] = []

        def run() -> None:
            try:
                outcome.append(
                    client.run(
                        [str(Path(sys.executable).resolve()), str(candidate)],
                        candidate_cwd=self.root,
                    )
                )
            except BaseException as error:
                outcome.append(error)

        thread = Thread(target=run)
        thread.start()
        pid_file = self.root / "candidate.pid"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not pid_file.exists():
            time.sleep(0.02)
        self.assertTrue(pid_file.exists(), outcome)
        candidate_pid = int(pid_file.read_text(encoding="utf-8"))

        report = registry.cancel_all(timeout_seconds=0.8)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(1, report.registered)
        self.assertEqual(0, report.remaining)
        self.assertTrue(outcome)
        self.assertIsInstance(outcome[0], BaseException)
        with self.assertRaises(ProcessLookupError):
            os.kill(candidate_pid, 0)

    def test_end_to_end_worker_returns_only_signed_weighted_aggregate(self) -> None:
        secret = "EXPECTATION_MUST_NOT_LEAK_9f4d"
        suite = self.write_suite(
            [
                {"id": "one", "input": {"n": 2}, "expected": 4, "weight_micros": 3},
                {"id": "two", "input": {"n": 3}, "expected": 6, "weight_micros": 7},
                {"id": "secret", "input": {"n": 9}, "expected": secret, "weight_micros": 11},
            ]
        )
        candidate = self.write_candidate(
            "import json,sys\n"
            "request=json.load(sys.stdin)\n"
            "n=request['input']['n']\n"
            "json.dump({'output': n*2},sys.stdout)\n"
        )
        receipt = self.client(suite).run(
            [str(Path(sys.executable).resolve()), str(candidate)],
            candidate_cwd=self.root,
            nonce="request-12345678",
        )
        payload = self.verifier.verify(
            receipt,
            expected_purpose="hidden-benchmark-aggregate",
            expected_tenant_id="benchmark-service",
        )
        result = payload["result"]
        self.assertEqual(result["passed"], 2)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["weighted_score_micros"], 10)
        self.assertEqual(result["max_score_micros"], 21)
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertNotIn(secret, rendered)
        self.assertNotIn('"expected"', rendered)
        self.assertNotIn('"cases"', rendered)
        self.assertNotIn('"case_id"', rendered)

    def test_candidate_failure_timeout_and_invalid_json_remain_aggregate_only(self) -> None:
        suite = self.write_suite(
            [{"id": "only", "input": 1, "expected": 2, "weight_micros": 1}]
        )
        candidate = self.write_candidate("print('not-json')\n")
        receipt = self.client(suite).run(
            [str(Path(sys.executable).resolve()), str(candidate)], candidate_cwd=self.root
        )
        payload = self.verifier.verify(receipt)
        self.assertEqual(payload["result"]["failed"], 1)
        self.assertNotIn("not-json", json.dumps(receipt))

    def test_exact_candidate_allowlist_and_cwd_root_are_enforced(self) -> None:
        suite = self.write_suite(
            [{"id": "only", "input": 1, "expected": 1, "weight_micros": 1}]
        )
        client = self.client(suite)
        with self.assertRaises(BenchmarkSecurityError):
            client.run(["python3", "candidate.py"], candidate_cwd=self.root)
        outside = self.root.parent
        with self.assertRaises(BenchmarkSecurityError):
            client.run([str(Path(sys.executable).resolve()), "candidate.py"], candidate_cwd=outside)

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits required")
    def test_private_suite_permissions_and_symlinks_are_rejected(self) -> None:
        suite = self.write_suite(
            [{"id": "only", "input": 1, "expected": 1, "weight_micros": 1}]
        )
        suite.chmod(0o644)
        with self.assertRaises(BenchmarkSecurityError):
            opaque_suite_digest(suite)
        suite.chmod(0o600)
        link = self.root / "suite-link.json"
        link.symlink_to(suite)
        with self.assertRaises(BenchmarkSecurityError):
            opaque_suite_digest(link)

    def test_loader_rejects_duplicates_nonfinite_and_duplicate_case_ids(self) -> None:
        suite = self.root / "private.json"
        suite.write_text(
            '{"schema_version":1,"benchmark_id":"x","benchmark_id":"y","cases":[]}',
            encoding="utf-8",
        )
        suite.chmod(0o600)
        with self.assertRaises(BenchmarkSchemaError):
            load_private_benchmark_for_worker(suite)
        with self.assertRaises(BenchmarkSchemaError):
            strict_json_loads('{"x":NaN}')
        duplicate = self.write_suite(
            [
                {"id": "same", "input": 1, "expected": 1, "weight_micros": 1},
                {"id": "same", "input": 2, "expected": 2, "weight_micros": 1},
            ]
        )
        with self.assertRaises(BenchmarkSchemaError):
            load_private_benchmark_for_worker(duplicate)

    def test_signed_but_leaky_response_is_rejected(self) -> None:
        suite = self.write_suite(
            [{"id": "only", "input": 1, "expected": 1, "weight_micros": 1}]
        )
        candidate = self.write_candidate("pass\n")
        argv = [str(Path(sys.executable).resolve()), str(candidate)]
        payload = {
            "receipt_type": "hidden_benchmark.aggregate.v1",
            "receipt_id": "r",
            "request_nonce": "nonce-12345678",
            "issued_at": "now",
            "benchmark": {
                "id": "hidden-test-v1",
                "version": 1,
                "suite_sha256": opaque_suite_digest(suite),
                "case_count": 1,
            },
            "candidate": {"fingerprint_sha256": candidate_fingerprint(argv, cwd=self.root)},
            "result": {
                "passed": 1,
                "failed": 0,
                "total": 1,
                "weighted_score_micros": 1,
                "max_score_micros": 1,
                "normalized_score_ppm": 1000000,
            },
            "expected": "leak",
        }
        receipt = self.signer.sign(
            payload,
            purpose="hidden-benchmark-aggregate",
            tenant_id="benchmark-service",
            nonce="nonce-12345678",
        )
        with self.assertRaises(BenchmarkProtocolError):
            validate_aggregate_receipt(
                receipt,
                verifier=self.verifier,
                expected_tenant_id="benchmark-service",
                expected_nonce="nonce-12345678",
                expected_suite_sha256=opaque_suite_digest(suite),
                expected_candidate_fingerprint=candidate_fingerprint(argv, cwd=self.root),
            )

    def test_signed_receipt_replay_suite_mismatch_and_tampering_are_rejected(self) -> None:
        suite = self.write_suite(
            [{"id": "only", "input": 1, "expected": 2, "weight_micros": 1}]
        )
        candidate = self.write_candidate(
            "import json,sys\nr=json.load(sys.stdin);json.dump({'output':2},sys.stdout)\n"
        )
        argv = [str(Path(sys.executable).resolve()), str(candidate)]
        receipt = self.client(suite).run(argv, candidate_cwd=self.root, nonce="nonce-original")
        with self.assertRaises(BenchmarkProtocolError):
            validate_aggregate_receipt(
                receipt,
                verifier=self.verifier,
                expected_tenant_id="benchmark-service",
                expected_nonce="different-nonce",
                expected_suite_sha256=opaque_suite_digest(suite),
                expected_candidate_fingerprint=candidate_fingerprint(argv, cwd=self.root),
            )
        tampered = copy.deepcopy(receipt)
        tampered["payload"]["result"]["passed"] = 0
        with self.assertRaises(BenchmarkProtocolError):
            validate_aggregate_receipt(
                tampered,
                verifier=self.verifier,
                expected_tenant_id="benchmark-service",
                expected_nonce="nonce-original",
                expected_suite_sha256=opaque_suite_digest(suite),
                expected_candidate_fingerprint=candidate_fingerprint(argv, cwd=self.root),
            )


if __name__ == "__main__":
    unittest.main()
