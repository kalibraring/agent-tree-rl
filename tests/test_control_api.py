from __future__ import annotations

import hashlib
import http.client
import json
from dataclasses import replace
from pathlib import Path
import shutil
import sys
import tempfile
import time
from threading import Thread
import unittest
from unittest.mock import patch

from agent_tree_rl.engine import PolicyValueModel
from agent_tree_rl.api import ProductionHTTPServer, RequestHandler
from agent_tree_rl.config import Principal, Settings
from agent_tree_rl.control import ControlPlane
from agent_tree_rl.crypto import ReceiptSigner, ReceiptVerifier
from agent_tree_rl.hidden_benchmark import HiddenBenchmarkClient, HiddenBenchmarkConfig
from agent_tree_rl.metrics import Metrics
from agent_tree_rl.store import SQLiteStore
from agent_tree_rl.store import BudgetExceededError, ConflictError


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_KEY = b"main-control-plane-test-key-material-32-bytes-plus"
BENCH_KEY = b"hidden-benchmark-test-key-material-32-bytes-plus"


class ControlPlaneIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.suite = self.root / "private.json"
        shutil.copyfile(
            PROJECT_ROOT / "agent_tree_rl/fixtures/sample_policy.json", self.suite
        )
        self.suite.chmod(0o600)
        self.bench_key = self.root / "benchmark.key"
        self.bench_key.write_bytes(BENCH_KEY)
        self.bench_key.chmod(0o600)
        self.settings = Settings(
            host="127.0.0.1",
            port=0,
            data_dir=self.root,
            database_path=self.root / "control.sqlite3",
            receipt_keys_file=self.root / "unused-keys.json",
            admin_token_file=self.root / "unused-tokens.json",
            benchmark_dir=self.root,
            require_auth=False,
            allowed_commands=("/bin/echo",),
            allowed_cwd_roots=(self.root, PROJECT_ROOT),
            default_tenant_budget=20_000,
            require_separation_of_duties=False,
        )
        self.signer = ReceiptSigner({"main-v1": MAIN_KEY}, "main-v1")
        self.verifier = ReceiptVerifier(
            {"main-v1": MAIN_KEY, "bench-v1": BENCH_KEY}
        )
        self.store = SQLiteStore(
            self.settings.database_path, receipt_verifier=self.verifier
        )
        hidden = HiddenBenchmarkClient(
            HiddenBenchmarkConfig(
                worker_script=PROJECT_ROOT / "agent_tree_rl/workers/benchmark_worker.py",
                benchmark_path=self.suite,
                signing_key_path=self.bench_key,
                key_id="bench-v1",
                candidate_executables=(Path(sys.executable).resolve(),),
                candidate_cwd_roots=(PROJECT_ROOT,),
                python_executable=sys.executable,
            ),
            self.verifier,
        )
        self.metrics = Metrics()
        self.control = ControlPlane(
            settings=self.settings,
            store=self.store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=self.metrics,
            hidden_benchmark=hidden,
        )
        self.principal = Principal(
            "tenant-a", frozenset({"agent", "operator", "promoter", "auditor"})
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_draining_is_idempotent_and_removes_readiness_before_shutdown(self) -> None:
        self.assertTrue(self.control.readiness()["ready"])
        self.assertTrue(self.control.begin_draining())
        self.assertFalse(self.control.begin_draining())
        self.assertEqual("draining", self.control.health()["status"])
        readiness = self.control.readiness()
        self.assertFalse(readiness["ready"])
        self.assertFalse(readiness["accepting_work"])
        self.assertEqual("draining", readiness["lifecycle"])

    def test_decision_evidence_and_hidden_benchmark_are_signed_and_persisted(self) -> None:
        decision = self.control.run_decision(
            self.principal,
            {"simulations": 64, "seed": 7},
            idempotency_key="decision-key-0001",
        )
        duplicate = self.control.run_decision(
            self.principal,
            {"simulations": 64, "seed": 7},
            idempotency_key="decision-key-0001",
        )
        self.assertEqual(decision, duplicate)
        self.assertEqual(
            len(self.store.list_experience_receipts("tenant-a")), 1
        )

        evidence = self.control.run_evidence(
            self.principal,
            {
                "command_id": "cmd0",
                "arguments": ["attested"],
                "cwd": str(self.root),
            },
            idempotency_key="evidence-key-0001",
        )
        self.assertEqual(evidence["outcome"], "passed")
        stored = self.store.get_evidence_receipt(
            "tenant-a", evidence["receipt_id"]
        )
        self.assertEqual(stored["evidence_kind"], "subprocess")

        challenger = self.control.learner.train_challenger(PolicyValueModel())
        challenger_artifact = self.control._persist_artifact(
            "tenant-a",
            self.control.POLICY_FAMILY,
            challenger,
            metadata={"status": "benchmark-test"},
        )
        benchmark = self.control.evaluate_hidden_benchmark(
            self.principal,
            {"challenger_id": challenger_artifact["artifact_id"]},
            idempotency_key="benchmark-key-0001",
        )
        self.assertEqual(benchmark["passed"], benchmark["total"])
        self.assertEqual(benchmark["normalized_score_ppm"], 1_000_000)
        self.assertNotIn("expected", json.dumps(benchmark))

    def test_readiness_uses_bounded_store_probe_not_full_integrity_scan(self) -> None:
        with patch.object(
            self.store,
            "integrity_check",
            side_effect=AssertionError("readiness must not scan the database"),
        ):
            readiness = self.control.readiness()
        self.assertTrue(readiness["ready"])
        self.assertTrue(readiness["storage"]["ok"])
        self.assertNotIn("integrity", readiness["storage"])

    def test_unknown_operation_fields_fail_closed_before_work(self) -> None:
        cases = (
            lambda: self.control.run_decision(
                self.principal,
                {"simulation": 8},
                idempotency_key="unknown-decision-field",
            ),
            lambda: self.control.run_evidence(
                self.principal,
                {"command_id": "cmd0", "cwd": str(self.root), "environment": {}},
                idempotency_key="unknown-evidence-field",
            ),
            lambda: self.control.evaluate_hidden_benchmark(
                self.principal,
                {"challenger_id": "not-used", "suite": "public"},
                idempotency_key="unknown-benchmark-field",
            ),
            lambda: self.control.train_challenger(
                self.principal,
                {"episode": 1},
                idempotency_key="unknown-training-field",
            ),
            lambda: self.control.promote(
                self.principal,
                "not-used",
                {"force": True},
                idempotency_key="unknown-promotion-field",
            ),
            lambda: self.control.rollback(
                self.principal,
                self.control.POLICY_FAMILY,
                {"artifact_id": "not-used"},
                idempotency_key="unknown-rollback-field",
            ),
        )
        for operation in cases:
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ValueError, "unknown request fields"):
                    operation()
        self.assertEqual([], self.store.list_experience_receipts("tenant-a"))

    def test_operation_text_fields_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "family must be"):
            self.control.run_decision(
                self.principal,
                {"family": [self.control.POLICY_FAMILY]},
                idempotency_key="invalid-family-type",
            )
        with self.assertRaisesRegex(ValueError, "cwd are required"):
            self.control.run_evidence(
                self.principal,
                {"command_id": "cmd0", "cwd": "bad\x00cwd"},
                idempotency_key="invalid-cwd",
            )
        with self.assertRaisesRegex(ValueError, "reason must be"):
            self.control.rollback(
                self.principal,
                self.control.POLICY_FAMILY,
                {"reason": {"not": "text"}},
                idempotency_key="invalid-reason-type",
            )

    def test_rollback_uses_exact_current_generation_beyond_history_window(self) -> None:
        family = self.control.POLICY_FAMILY
        first = self.control._persist_artifact(
            "tenant-a", family, PolicyValueModel(generation=0), metadata={}
        )
        second = self.control._persist_artifact(
            "tenant-a", family, PolicyValueModel(generation=1), metadata={}
        )
        current = self.control._persist_artifact(
            "tenant-a", family, PolicyValueModel(generation=2), metadata={}
        )
        self.store.promote_policy(
            "tenant-a",
            family,
            first["artifact_id"],
            expected_current_artifact_id=None,
            decided_by="seed",
            reason="first",
        )
        rows = []
        previous = first["artifact_id"]
        for generation in range(2, 1001):
            artifact_id = (
                second["artifact_id"] if generation % 2 == 0 else first["artifact_id"]
            )
            rows.append(
                (
                    f"seed-{generation}",
                    "tenant-a",
                    family,
                    artifact_id,
                    previous,
                    generation,
                    "seed",
                    "history-window fixture",
                    None,
                    generation,
                )
            )
            previous = artifact_id
        rows.append(
            (
                "seed-1001",
                "tenant-a",
                family,
                current["artifact_id"],
                previous,
                1001,
                "seed",
                "current outside list window",
                None,
                1001,
            )
        )
        with self.store.transaction() as connection:
            connection.executemany(
                "INSERT INTO promotion_audit VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            connection.execute(
                "UPDATE champion_registry SET artifact_id=?, generation=?, promoted_at=? "
                "WHERE tenant_id=? AND policy_name=?",
                (current["artifact_id"], 1001, 1001, "tenant-a", family),
            )

        self.assertEqual(1000, len(self.store.list_promotion_audit("tenant-a", family)))
        result = self.control.rollback(
            self.principal,
            family,
            {"reason": "history window regression"},
            idempotency_key="rollback-history-window-0001",
        )

        self.assertEqual(previous, result["promotion"]["artifact_id"])
        self.assertEqual(1002, result["promotion"]["generation"])

    def test_identical_retraining_records_distinct_provenance(self) -> None:
        request = {"episodes": 1, "simulations": 8}
        first = self.control.train_challenger(
            self.principal,
            request,
            idempotency_key="deterministic-training-a",
        )
        second = self.control.train_challenger(
            self.principal,
            request,
            idempotency_key="deterministic-training-b",
        )

        self.assertEqual(first["challenger_id"], second["challenger_id"])
        self.assertEqual("deterministic-training-a", first["training_id"])
        self.assertEqual("deterministic-training-b", second["training_id"])
        runs = self.store.list_training_runs(
            "tenant-a", first["challenger_id"]
        )
        self.assertCountEqual(
            ["deterministic-training-a", "deterministic-training-b"],
            [run.training_id for run in runs],
        )
        self.assertEqual(2, len({run.lease_fencing_token for run in runs}))
        self.assertEqual(
            {self.principal.subject_id},
            set(self.store.training_producers("tenant-a", first["challenger_id"])),
        )
        artifact = self.store.get_policy_artifact(
            "tenant-a", first["challenger_id"]
        )
        self.assertEqual({"status": "challenger"}, artifact["metadata"])
        budget = self.store.get_budget("tenant-a", "api-compute")
        self.assertEqual((0, 16), (budget.reserved_units, budget.consumed_units))

    def test_train_promote_restart_and_rollback(self) -> None:
        cold_artifact = self.control._persist_artifact(
            "tenant-a",
            self.control.POLICY_FAMILY,
            PolicyValueModel(),
            metadata={"status": "bootstrap-champion"},
        )
        self.store.promote_policy(
            "tenant-a",
            self.control.POLICY_FAMILY,
            cold_artifact["artifact_id"],
            expected_current_artifact_id=None,
            decided_by="test-bootstrap",
            reason="bootstrap cold champion",
        )
        champion_benchmark = self.control.evaluate_hidden_benchmark(
            self.principal,
            {"challenger_id": cold_artifact["artifact_id"]},
            idempotency_key="champion-benchmark-key-0001",
        )
        trained = self.control.train_challenger(
            self.principal,
            {"episodes": 12, "simulations": 128},
            idempotency_key="training-key-0001",
        )
        self.assertTrue(trained["promotion_report"]["accepted"])
        benchmark = self.control.evaluate_hidden_benchmark(
            self.principal,
            {"challenger_id": trained["challenger_id"]},
            idempotency_key="promotion-benchmark-key-0001",
        )
        with self.assertRaisesRegex(ConflictError, "different challenger"):
            self.control.promote(
                self.principal,
                trained["challenger_id"],
                {
                    "reason": "swapped receipt must fail",
                    "hidden_benchmark_receipt_id": champion_benchmark["receipt_id"],
                    "champion_hidden_benchmark_receipt_id": benchmark["receipt_id"],
                },
                idempotency_key="swapped-promotion-key-0001",
            )
        with self.assertRaisesRegex(ConflictError, "different challenger"):
            self.control.promote(
                self.principal,
                trained["challenger_id"],
                {
                    "reason": "wrong champion receipt must fail",
                    "hidden_benchmark_receipt_id": benchmark["receipt_id"],
                    "champion_hidden_benchmark_receipt_id": benchmark["receipt_id"],
                },
                idempotency_key="wrong-champion-receipt-key-0001",  # gitleaks:allow
            )
        self.assertEqual(
            cold_artifact["artifact_id"],
            self.store.get_champion("tenant-a", self.control.POLICY_FAMILY)["artifact_id"],
        )
        self.assertEqual(
            1,
            len(
                self.store.list_promotion_audit(
                    "tenant-a", self.control.POLICY_FAMILY
                )
            ),
        )
        promoted = self.control.promote(
            self.principal,
            trained["challenger_id"],
            {
                "reason": "paired gates passed",
                "hidden_benchmark_receipt_id": benchmark["receipt_id"],
                "champion_hidden_benchmark_receipt_id": champion_benchmark["receipt_id"],
            },
            idempotency_key="promotion-key-0001",
        )
        self.assertEqual(
            promoted["promotion"]["artifact_id"], trained["challenger_id"]
        )

        # Close/reopen proves the champion pointer and content-addressed artifact survive.
        self.store.close()
        self.store = SQLiteStore(
            self.settings.database_path, receipt_verifier=self.verifier
        )
        restarted = ControlPlane(
            settings=self.settings,
            store=self.store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=Metrics(),
            hidden_benchmark=self.control.hidden_benchmark,
        )
        champion = restarted.get_champion(
            self.principal, self.control.POLICY_FAMILY
        )["champion"]
        self.assertEqual(champion["artifact_id"], trained["challenger_id"])
        with patch.object(
            restarted.store,
            "append_event",
            side_effect=OSError("audit sink failure"),
        ):
            with self.assertRaisesRegex(OSError, "audit sink failure"):
                restarted.rollback(
                    self.principal,
                    self.control.POLICY_FAMILY,
                    {"reason": "fault injection"},
                    idempotency_key="rollback-fault-key-0001",
                )
        unchanged = restarted.get_champion(
            self.principal, self.control.POLICY_FAMILY
        )["champion"]
        self.assertEqual(trained["challenger_id"], unchanged["artifact_id"])
        self.assertEqual(
            2,
            len(
                restarted.store.list_promotion_audit(
                    "tenant-a", self.control.POLICY_FAMILY
                )
            ),
        )
        with patch.object(
            restarted.store,
            "complete_idempotency",
            side_effect=OSError("idempotency finalize failure"),
        ):
            with self.assertRaisesRegex(OSError, "idempotency finalize failure"):
                restarted.rollback(
                    self.principal,
                    self.control.POLICY_FAMILY,
                    {"reason": "finalize fault injection"},
                    idempotency_key="rollback-finalize-fault-key",
                )
        still_unchanged = restarted.get_champion(
            self.principal, self.control.POLICY_FAMILY
        )["champion"]
        self.assertEqual(trained["challenger_id"], still_unchanged["artifact_id"])
        self.assertEqual(
            2,
            len(
                restarted.store.list_promotion_audit(
                    "tenant-a", self.control.POLICY_FAMILY
                )
            ),
        )
        self.assertFalse(
            any(
                event["event_type"] == "POLICY_ROLLED_BACK"
                for event in restarted.store.list_events("tenant-a")
            )
        )
        rolled_back = restarted.rollback(
            self.principal,
            self.control.POLICY_FAMILY,
            {"reason": "drill"},
            idempotency_key="rollback-key-0001",
        )
        self.assertEqual(
            rolled_back["promotion"]["artifact_id"], cold_artifact["artifact_id"]
        )
        self.assertEqual(self.principal.subject_id, rolled_back["promotion"]["decided_by"])

    def test_promotion_rejects_benchmark_for_different_or_weak_artifact(self) -> None:
        cold_artifact = self.control._persist_artifact(
            "tenant-a",
            self.control.POLICY_FAMILY,
            PolicyValueModel(),
            metadata={"status": "cold"},
        )
        cold_benchmark = self.control.evaluate_hidden_benchmark(
            self.principal,
            {"challenger_id": cold_artifact["artifact_id"]},
            idempotency_key="cold-benchmark-key-0001",
        )
        self.assertLess(cold_benchmark["normalized_score_ppm"], 900_000)
        with self.assertRaisesRegex(ConflictError, "below promotion threshold"):
            self.control._validate_promotion_benchmark(
                "tenant-a",
                cold_artifact["artifact_id"],
                cold_benchmark["receipt_id"],
            )

        trained = self.control.learner.train_challenger(PolicyValueModel())
        trained_artifact = self.control._persist_artifact(
            "tenant-a",
            self.control.POLICY_FAMILY,
            trained,
            metadata={"status": "trained"},
        )
        with self.assertRaisesRegex(ConflictError, "different challenger"):
            self.control._validate_promotion_benchmark(
                "tenant-a",
                trained_artifact["artifact_id"],
                cold_benchmark["receipt_id"],
            )

    def test_tenant_cannot_read_another_tenant_champion(self) -> None:
        artifact = self.control._persist_artifact(
            "tenant-a",
            self.control.POLICY_FAMILY,
            PolicyValueModel(),
            metadata={},
        )
        self.store.promote_policy(
            "tenant-a",
            self.control.POLICY_FAMILY,
            artifact["artifact_id"],
            expected_current_artifact_id=None,
            decided_by="test",
            reason="test",
        )
        other = Principal("tenant-b", frozenset({"auditor"}))
        self.assertIsNone(
            self.control.get_champion(other, self.control.POLICY_FAMILY)["champion"]
        )

    def test_hidden_attempt_quota_and_promoter_separation_are_enforced(self) -> None:
        governed = ControlPlane(
            settings=replace(
                self.settings,
                require_separation_of_duties=True,
                hidden_benchmark_attempt_limit=3,
            ),
            store=self.store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=Metrics(),
            hidden_benchmark=self.control.hidden_benchmark,
        )
        trainer = Principal(
            "tenant-a",
            frozenset({"agent", "promoter"}),
            "trainer-subject",
        )
        reviewer = Principal(
            "tenant-a",
            frozenset({"promoter"}),
            "reviewer-subject",
        )
        cold = governed._persist_artifact(
            "tenant-a", governed.POLICY_FAMILY, PolicyValueModel(), metadata={}
        )
        self.store.promote_policy(
            "tenant-a",
            governed.POLICY_FAMILY,
            cold["artifact_id"],
            expected_current_artifact_id=None,
            decided_by="bootstrap",
            reason="bootstrap",
        )
        with self.assertRaisesRegex(ConflictError, "producer identity is missing"):
            governed.promote(
                reviewer,
                cold["artifact_id"],
                {},
                idempotency_key="missing-provenance-promotion",
            )
        champion_benchmark = governed.evaluate_hidden_benchmark(
            reviewer,
            {"challenger_id": cold["artifact_id"]},
            idempotency_key="governed-cold-benchmark",
        )
        trained = governed.train_challenger(
            trainer,
            {"episodes": 12, "simulations": 128},
            idempotency_key="governed-train",
        )
        challenger_benchmark = governed.evaluate_hidden_benchmark(
            reviewer,
            {"challenger_id": trained["challenger_id"]},
            idempotency_key="governed-challenger-benchmark",
        )
        request = {
            "hidden_benchmark_receipt_id": challenger_benchmark["receipt_id"],
            "champion_hidden_benchmark_receipt_id": champion_benchmark["receipt_id"],
        }
        with self.assertRaisesRegex(ConflictError, "different subjects"):
            governed.promote(
                trainer,
                trained["challenger_id"],
                request,
                idempotency_key="same-subject-promotion",
            )
        promoted = governed.promote(
            reviewer,
            trained["challenger_id"],
            request,
            idempotency_key="reviewer-promotion",
        )
        self.assertEqual("reviewer-subject", promoted["promotion"]["decided_by"])

        for attempt in range(2):
            governed.evaluate_hidden_benchmark(
                reviewer,
                {"challenger_id": trained["challenger_id"]},
                idempotency_key=f"extra-benchmark-{attempt}",
            )
        self.store.close()
        self.store = SQLiteStore(
            self.settings.database_path, receipt_verifier=self.verifier
        )
        restarted = ControlPlane(
            settings=replace(
                self.settings,
                require_separation_of_duties=True,
                hidden_benchmark_attempt_limit=3,
            ),
            store=self.store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=Metrics(),
            hidden_benchmark=self.control.hidden_benchmark,
        )
        with self.assertRaises(BudgetExceededError):
            restarted.evaluate_hidden_benchmark(
                reviewer,
                {"challenger_id": trained["challenger_id"]},
                idempotency_key="over-quota-benchmark",
            )
        next_window = time.time() + self.settings.hidden_benchmark_quota_window_seconds + 1
        with patch("agent_tree_rl.control.time.time", return_value=next_window):
            reset = restarted.evaluate_hidden_benchmark(
                reviewer,
                {"challenger_id": trained["challenger_id"]},
                idempotency_key="next-window-benchmark",
            )
        self.assertEqual(1_000_000, reset["normalized_score_ppm"])

    def test_expired_training_worker_is_fenced_before_artifact_commit(self) -> None:
        clock = [int(time.time())]
        self.store._clock = lambda: clock[0]
        governed = ControlPlane(
            settings=replace(self.settings, lease_seconds=5),
            store=self.store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=Metrics(),
            hidden_benchmark=self.control.hidden_benchmark,
        )
        trainer = Principal("tenant-a", frozenset({"agent"}), "stale-trainer")
        original_train = governed.learner.train_challenger

        def train_then_lose_lease(champion: PolicyValueModel, **kwargs: object) -> PolicyValueModel:
            model = original_train(champion, **kwargs)
            clock[0] += 1000
            self.store.acquire_lease(
                "tenant-a",
                f"train:{governed.POLICY_FAMILY}",
                "replacement-trainer",
                ttl_seconds=60,
            )
            return model

        before = int(
            self.store._fetchone("SELECT COUNT(*) FROM policy_artifacts")[0]
        )
        with patch.object(
            governed.learner,
            "train_challenger",
            side_effect=train_then_lose_lease,
        ):
            with self.assertRaisesRegex(ConflictError, "stale"):
                governed.train_challenger(
                    trainer,
                    {"episodes": 1, "simulations": 8},
                    idempotency_key="stale-training-key-0001",
                )
        after = int(
            self.store._fetchone("SELECT COUNT(*) FROM policy_artifacts")[0]
        )
        self.assertEqual(before, after)
        self.assertFalse(
            any(
                event["event_type"] == "CHALLENGER_TRAINED"
                for event in self.store.list_events("tenant-a")
            )
        )
        lease = self.store.get_lease(
            "tenant-a", f"train:{governed.POLICY_FAMILY}"
        )
        self.assertEqual("replacement-trainer", lease.holder_id)


class AuthenticatedAPITests(unittest.TestCase):
    def test_api_requires_token_and_honors_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            token = "api-test-token-with-high-entropy"
            digest = hashlib.sha256(token.encode()).hexdigest()
            settings = Settings(
                host="127.0.0.1",
                port=0,
                data_dir=root,
                database_path=root / "api.sqlite3",
                receipt_keys_file=root / "unused-key",
                admin_token_file=root / "unused-token",
                benchmark_dir=root,
                require_auth=True,
                token_digests={
                    digest: Principal(
                        "tenant-api", frozenset({"agent", "operator", "auditor"})
                        , "api-test-subject"
                    )
                },
                allowed_commands=(str(Path(sys.executable).resolve()),),
                allowed_cwd_roots=(root,),
            )
            signer = ReceiptSigner({"main": MAIN_KEY}, "main")
            verifier = ReceiptVerifier({"main": MAIN_KEY})
            store = SQLiteStore(settings.database_path, receipt_verifier=verifier)
            control = ControlPlane(
                settings=settings,
                store=store,
                signer=signer,
                verifier=verifier,
                metrics=Metrics(),
            )
            server = ProductionHTTPServer(
                ("127.0.0.1", 0),
                RequestHandler,
                settings=settings,
                control=control,
                metrics=control.metrics,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=10
                )
                body = json.dumps({"simulations": 64, "seed": 7})
                connection.request(
                    "POST",
                    "/v1/decisions/run",
                    body=body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                        "Idempotency-Key": "api-idempotency-0001",
                    },
                )
                unauthorized = connection.getresponse()
                unauthorized.read()
                self.assertEqual(unauthorized.status, 401)

                connection.request(
                    "POST",
                    "/v1/decisions/run",
                    body=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                        "Idempotency-Key": "api-idempotency-0001",
                    },
                )
                response = connection.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200, payload)
                self.assertEqual(payload["experience_receipt_id"],
                                 control.run_decision(
                                     Principal("tenant-api", frozenset({"agent"})),
                                     {"simulations": 64, "seed": 7},
                                     idempotency_key="api-idempotency-0001",
                                 )["experience_receipt_id"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                store.close()

    def test_api_role_matrix_and_cross_tenant_champion_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tokens = {
                "agent": "agent-token-high-entropy",
                "operator": "operator-token-high-entropy",
                "promoter": "promoter-token-high-entropy",
                "auditor": "auditor-token-high-entropy",
                "other_auditor": "other-tenant-auditor-token",
                "other_agent": "other-tenant-agent-token",
                "other_promoter": "other-tenant-promoter-token",
            }
            principals = {
                role: Principal(
                    "tenant-b" if role.startswith("other_") else "tenant-a",
                    frozenset({role.split("_", 1)[1] if role.startswith("other_") else role}),
                    f"{role}-subject",
                )
                for role in tokens
            }
            settings = Settings(
                host="127.0.0.1",
                port=0,
                data_dir=root,
                database_path=root / "rbac.sqlite3",
                receipt_keys_file=root / "unused-key",
                admin_token_file=root / "unused-token",
                benchmark_dir=root,
                require_auth=True,
                token_digests={
                    hashlib.sha256(token.encode()).hexdigest(): principals[role]
                    for role, token in tokens.items()
                },
                allowed_commands=("/bin/echo",),
                allowed_cwd_roots=(root,),
            )
            signer = ReceiptSigner({"main": MAIN_KEY}, "main")
            verifier = ReceiptVerifier({"main": MAIN_KEY})
            store = SQLiteStore(settings.database_path, receipt_verifier=verifier)
            control = ControlPlane(
                settings=settings,
                store=store,
                signer=signer,
                verifier=verifier,
                metrics=Metrics(),
            )
            artifact = control._persist_artifact(
                "tenant-a", control.POLICY_FAMILY, PolicyValueModel(), metadata={}
            )
            store.promote_policy(
                "tenant-a",
                control.POLICY_FAMILY,
                artifact["artifact_id"],
                expected_current_artifact_id=None,
                decided_by="bootstrap",
                reason="rbac fixture",
            )
            server = ProductionHTTPServer(
                ("127.0.0.1", 0),
                RequestHandler,
                settings=settings,
                control=control,
                metrics=control.metrics,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def request(
                method: str,
                route: str,
                role: str,
                body: object | None = None,
                key: str = "rbac-key-0001",
            ) -> tuple[int, dict[str, object]]:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=10
                )
                if body is None:
                    encoded = b""
                elif isinstance(body, bytes):
                    encoded = body
                elif isinstance(body, str):
                    encoded = body.encode()
                else:
                    encoded = json.dumps(body).encode()
                headers = {"Authorization": f"Bearer {tokens[role]}"}
                if method == "POST":
                    headers.update(
                        {
                            "Content-Type": "application/json",
                            "Content-Length": str(len(encoded)),
                            "Idempotency-Key": key,
                        }
                    )
                connection.request(method, route, body=encoded, headers=headers)
                response = connection.getresponse()
                payload = json.loads(response.read())
                connection.close()
                return response.status, payload

            try:
                self.assertEqual(
                    200,
                    request(
                        "POST",
                        "/v1/decisions/run",
                        "agent",
                        {"simulations": 8},
                    )[0],
                )
                self.assertEqual(
                    403,
                    request(
                        "POST",
                        "/v1/decisions/run",
                        "auditor",
                        {"simulations": 8},
                        "rbac-key-0002",
                    )[0],
                )
                self.assertEqual(
                    403,
                    request(
                        "POST",
                        "/v1/benchmarks/evaluate",
                        "agent",
                        {"challenger_id": artifact["artifact_id"]},
                        "rbac-key-0003",
                    )[0],
                )
                self.assertEqual(
                    400,
                    request(
                        "POST",
                        "/v1/benchmarks/evaluate",
                        "promoter",
                        {"challenger_id": artifact["artifact_id"]},
                        "rbac-key-0004",
                    )[0],
                )
                self.assertEqual(
                    200,
                    request(
                        "POST",
                        "/v1/challengers/train",
                        "agent",
                        {"episodes": 1, "simulations": 8},
                        "rbac-key-0005",
                    )[0],
                )
                self.assertEqual(
                    403,
                    request(
                        "POST",
                        "/v1/challengers/train",
                        "promoter",
                        {"episodes": 1, "simulations": 8},
                        "rbac-key-0006",
                    )[0],
                )
                self.assertEqual(
                    403,
                    request(
                        "POST",
                        f"/v1/challengers/{artifact['artifact_id']}/promote",
                        "agent",
                        {},
                        "rbac-key-0007",
                    )[0],
                )
                self.assertEqual(
                    403,
                    request(
                        "GET",
                        f"/v1/families/{control.POLICY_FAMILY}/champion",
                        "agent",
                    )[0],
                )
                status, own = request(
                    "GET",
                    f"/v1/families/{control.POLICY_FAMILY}/champion",
                    "auditor",
                )
                self.assertEqual(200, status)
                self.assertEqual(artifact["artifact_id"], own["champion"]["artifact_id"])
                status, other = request(
                    "GET",
                    f"/v1/families/{control.POLICY_FAMILY}/champion",
                    "other_auditor",
                )
                self.assertEqual(200, status)
                self.assertIsNone(other["champion"])
                self.assertEqual(403, request("GET", "/v1/audit", "agent")[0])
                self.assertEqual(200, request("GET", "/v1/audit", "auditor")[0])

                roles = {"agent", "operator", "promoter", "auditor"}
                post_matrix = (
                    (
                        "/v1/decisions/run",
                        {"simulations": 8},
                        {"agent"},
                    ),
                    (
                        "/v1/evidence/run",
                        {
                            "command_id": "cmd0",
                            "arguments": ["rbac"],
                            "cwd": str(root),
                        },
                        {"operator"},
                    ),
                    (
                        "/v1/benchmarks/evaluate",
                        {"challenger_id": artifact["artifact_id"]},
                        {"promoter"},
                    ),
                    (
                        "/v1/challengers/train",
                        {"episodes": 1, "simulations": 8},
                        {"agent"},
                    ),
                    (
                        "/v1/challengers/not-a-real-artifact/promote",
                        {},
                        {"promoter"},
                    ),
                    (
                        f"/v1/families/{control.POLICY_FAMILY}/rollback",
                        {},
                        {"promoter"},
                    ),
                )
                counter = 100
                for route, body, allowed in post_matrix:
                    for role in sorted(roles):
                        counter += 1
                        status, _ = request(
                            "POST",
                            route,
                            role,
                            body,
                            f"matrix-key-{counter:04d}",
                        )
                        if role in allowed:
                            self.assertNotEqual(403, status, (route, role))
                        else:
                            self.assertEqual(403, status, (route, role))

                malformed_routes = (
                    f"/v1/challengers/{artifact['artifact_id']}/extra/promote",
                    f"/v1/challengers/{artifact['artifact_id']}/promote/",
                    "/v1/challengers//promote",
                    f"/v1/families/{control.POLICY_FAMILY}/extra/champion",
                    f"/v1/families/{control.POLICY_FAMILY}/champion/",
                    "/v1/families//champion",
                    f"/v1/families/{control.POLICY_FAMILY}/extra/rollback",
                )
                for index, route in enumerate(malformed_routes):
                    method = "GET" if "champion" in route else "POST"
                    status, _ = request(
                        method,
                        route,
                        "promoter",
                        {} if method == "POST" else None,
                        f"malformed-route-{index:04d}",
                    )
                    self.assertEqual(404, status, route)

                metrics = control.metrics.render()
                self.assertIn(
                    'route="/v1/challengers/{challenger_id}/promote"', metrics
                )
                self.assertIn('route="unmatched"', metrics)
                self.assertNotIn(artifact["artifact_id"], metrics)
                self.assertNotIn(control.POLICY_FAMILY, metrics)

                with patch("agent_tree_rl.api.LOGGER.info") as log_info:
                    status, _ = request(
                        "GET",
                        f"/v1/families/{control.POLICY_FAMILY}/champion",
                        "auditor",
                    )
                self.assertEqual(200, status)
                logged = log_info.call_args.kwargs["extra"]
                self.assertEqual(
                    "/v1/families/{family}/champion", logged["route"]
                )
                self.assertTrue(logged["authenticated"])
                self.assertNotIn("tenant_id", logged)
                self.assertNotIn(control.POLICY_FAMILY, logged.values())

                with patch("agent_tree_rl.api.LOGGER.info") as log_info:
                    status, _ = request(
                        "GET",
                        f"/v1/families/{control.POLICY_FAMILY}/extra/champion",
                        "auditor",
                    )
                self.assertEqual(404, status)
                self.assertEqual(
                    "unmatched", log_info.call_args.kwargs["extra"]["route"]
                )

                for role in sorted(roles):
                    status, _ = request(
                        "GET",
                        f"/v1/families/{control.POLICY_FAMILY}/champion",
                        role,
                    )
                    self.assertEqual(403 if role == "agent" else 200, status)
                    status, _ = request("GET", "/v1/audit", role)
                    self.assertEqual(
                        200 if role in {"operator", "auditor"} else 403,
                        status,
                    )

                invalid_queries = (
                    "/v1/audit?unknown=",
                    "/v1/audit?after=",
                    "/v1/audit?after",
                    "/v1/audit?after=1&after=2",
                    "/v1/audit?after=-1",
                    "/v1/audit?after=%EF%BC%91",
                    "/v1/audit?after=9223372036854775808",
                    "/v1/audit?limit=0",
                    "/v1/audit?limit=501",
                    "/v1/audit?after=1&limit=2&x=3&y=4&z=5",
                )
                for route in invalid_queries:
                    status, payload = request("GET", route, "auditor")
                    self.assertEqual(400, status, route)
                    self.assertEqual("invalid_query", payload["error"]["code"])

                self.assertEqual(
                    200,
                    request(
                        "GET",
                        "/v1/audit?after=9223372036854775807&limit=500",
                        "auditor",
                    )[0],
                )
                self.assertEqual(
                    400,
                    request(
                        "GET",
                        f"/v1/families/{control.POLICY_FAMILY}/champion?extra=1",
                        "auditor",
                    )[0],
                )

                deep_value: object = 8
                for _ in range(64):
                    deep_value = [deep_value]
                invalid_json_bodies = (
                    '{"simulations":8,"simulations":16}',
                    '{"simulations":NaN}',
                    '{"simulations":Infinity}',
                    '{"simulations":1e999}',
                    {"simulations": deep_value},
                    {"values": [0] * 10_000},
                )
                for index, invalid_body in enumerate(invalid_json_bodies):
                    status, payload = request(
                        "POST",
                        "/v1/decisions/run",
                        "agent",
                        invalid_body,
                        f"invalid-json-{index:04d}",
                    )
                    self.assertEqual(400, status, index)
                    self.assertEqual(
                        {
                            "code": "invalid_json",
                            "message": "invalid JSON body",
                        },
                        payload["error"],
                    )
                    self.assertNotIn(str(invalid_body), json.dumps(payload))

                shared_key = "cross-tenant-shared-key"
                own_status, own_decision = request(
                    "POST",
                    "/v1/decisions/run",
                    "agent",
                    {"simulations": 8},
                    shared_key,
                )
                other_status, other_decision = request(
                    "POST",
                    "/v1/decisions/run",
                    "other_agent",
                    {"simulations": 8},
                    shared_key,
                )
                self.assertEqual((200, 200), (own_status, other_status))
                self.assertNotEqual(own_decision["run_id"], other_decision["run_id"])
                cross_status, _ = request(
                    "POST",
                    f"/v1/challengers/{artifact['artifact_id']}/promote",
                    "other_promoter",
                    {},
                    "cross-tenant-promotion-key",
                )
                self.assertEqual(404, cross_status)
                audit_status, other_audit = request(
                    "GET", "/v1/audit", "other_auditor"
                )
                self.assertEqual(200, audit_status)
                self.assertTrue(other_audit["events"])
                self.assertNotIn("tenant-a", json.dumps(other_audit))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                store.close()


if __name__ == "__main__":
    unittest.main()
