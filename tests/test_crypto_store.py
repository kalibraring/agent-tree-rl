from __future__ import annotations

import copy
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_tree_rl.crypto import (
    ExpiredReceiptError,
    InvalidEnvelopeError,
    InvalidSignatureError,
    NotYetValidReceiptError,
    ReceiptSigner,
    ReceiptVerifier,
    ReplayDetectedError,
    UnknownKeyError,
    canonical_json_bytes,
)
from agent_tree_rl.store import (
    BudgetExceededError,
    ConflictError,
    LeaseUnavailableError,
    SQLiteStore,
    StoreConfigurationError,
)


KEY_A = b"a" * 32
KEY_B = b"b" * 32
TENANT = "tenant-a"


class MutableClock:
    def __init__(self, value: int = 1_700_000_000) -> None:
        self.value = value

    def __call__(self) -> float:
        return float(self.value)


class CryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock()
        self.signer = ReceiptSigner(
            {"2026-a": KEY_A, "2026-b": KEY_B}, "2026-a", clock=self.clock
        )
        self.verifier = ReceiptVerifier(
            {"2026-a": KEY_A, "2026-b": KEY_B},
            clock=self.clock,
            clock_skew_seconds=0,
        )

    def test_canonical_json_is_order_independent_unicode_and_compact(self) -> None:
        left = {"z": [3, {"é": True}], "a": 1.5}
        right = {"a": 1.5, "z": [3, {"é": True}]}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))
        self.assertEqual(
            canonical_json_bytes(left).decode(), '{"a":1.5,"z":[3,{"é":true}]}'
        )

    def test_canonical_json_rejects_non_json_and_nonfinite_values(self) -> None:
        with self.assertRaises(InvalidEnvelopeError):
            canonical_json_bytes({"bad": float("nan")})
        with self.assertRaises(InvalidEnvelopeError):
            canonical_json_bytes({1: "integer-key"})
        with self.assertRaises(InvalidEnvelopeError):
            canonical_json_bytes({"set": {1, 2}})

    def test_sign_verify_binds_every_field_and_returns_detached_payload(self) -> None:
        payload = {"subject_id": "run-1", "facts": ["α", "β"]}
        envelope = self.signer.sign(
            payload,
            purpose="evidence",
            tenant_id=TENANT,
            ttl_seconds=60,
            nonce="nonce-1",
        )
        verified = self.verifier.verify(
            envelope, expected_purpose="evidence", expected_tenant_id=TENANT
        )
        self.assertEqual(payload, verified)
        verified["facts"].append("changed")
        self.assertEqual(["α", "β"], envelope["payload"]["facts"])

        for field, replacement in (
            ("tenant_id", "tenant-b"),
            ("purpose", "experience"),
            ("nonce", "nonce-2"),
            ("expires_at", envelope["expires_at"] + 1),
            ("payload", {"subject_id": "tampered"}),
        ):
            tampered = copy.deepcopy(envelope)
            tampered[field] = replacement
            with self.subTest(field=field), self.assertRaises(InvalidSignatureError):
                self.verifier.verify(tampered)

    def test_expiry_future_issue_scope_and_shape_fail_closed(self) -> None:
        envelope = self.signer.sign(
            {"ok": True},
            purpose="evidence",
            tenant_id=TENANT,
            ttl_seconds=10,
        )
        with self.assertRaises(InvalidEnvelopeError):
            self.verifier.verify(envelope, expected_purpose="experience")
        with self.assertRaises(InvalidEnvelopeError):
            self.verifier.verify(envelope, expected_tenant_id="tenant-b")

        self.clock.value += 11
        with self.assertRaises(ExpiredReceiptError):
            self.verifier.verify(envelope)

        future = self.signer.sign(
            {"ok": True},
            purpose="evidence",
            tenant_id=TENANT,
            issued_at=self.clock.value + 1,
        )
        with self.assertRaises(NotYetValidReceiptError):
            self.verifier.verify(future)

        malformed = copy.deepcopy(envelope)
        malformed["unsigned_extension"] = "forbidden"
        with self.assertRaises(InvalidEnvelopeError):
            self.verifier.verify(malformed)

    def test_key_rotation_unknown_key_and_replay_hook(self) -> None:
        old = self.signer.sign(
            {"n": 1}, purpose="experience", tenant_id=TENANT, nonce="same"
        )
        new_signer = ReceiptSigner(
            {"2026-a": KEY_A, "2026-b": KEY_B}, "2026-b", clock=self.clock
        )
        new = new_signer.sign(
            {"n": 2}, purpose="experience", tenant_id=TENANT, nonce="other"
        )
        self.assertEqual({"n": 1}, self.verifier.verify(old))
        self.assertEqual({"n": 2}, self.verifier.verify(new))

        unknown = ReceiptVerifier({"2026-b": KEY_B}, clock=self.clock)
        with self.assertRaises(UnknownKeyError):
            unknown.verify(old)

        claims: set[tuple[str, str, str]] = set()

        def claim(tenant: str, purpose: str, nonce: str, _: int | None) -> bool:
            identity = (tenant, purpose, nonce)
            if identity in claims:
                return False
            claims.add(identity)
            return True

        self.verifier.verify(old, replay_guard=claim)
        with self.assertRaises(ReplayDetectedError):
            self.verifier.verify(old, replay_guard=claim)

        # A persistence layer can explicitly disable the verifier default and
        # claim the nonce in the same transaction as its durable insert.
        default_guard_verifier = ReceiptVerifier(
            {"2026-a": KEY_A}, clock=self.clock, replay_guard=lambda *_: False
        )
        self.assertEqual({"n": 1}, default_guard_verifier.verify(old, replay_guard=None))

    def test_requires_strong_keys_and_positive_ttl(self) -> None:
        with self.assertRaises(ValueError):
            ReceiptSigner({"weak": b"short"}, "weak")
        with self.assertRaises(ValueError):
            self.signer.sign({}, purpose="x", tenant_id=TENANT, ttl_seconds=0)


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "control.db"
        self.clock = MutableClock()
        self.signer = ReceiptSigner({"key-a": KEY_A}, "key-a", clock=self.clock)
        self.verifier = ReceiptVerifier(
            {"key-a": KEY_A}, clock=self.clock, clock_skew_seconds=0
        )
        self.store = SQLiteStore(
            self.path,
            receipt_verifier=self.verifier,
            clock=self.clock,
            replay_grace_seconds=30,
        )
        self.addCleanup(self.store.close)

    def test_wal_migration_health_reopen_and_integrity(self) -> None:
        with patch.object(
            self.store,
            "integrity_check",
            side_effect=AssertionError("readiness must remain bounded"),
        ):
            readiness = self.store.readiness_check()
        self.assertTrue(readiness["ok"])
        self.assertEqual(1, readiness["schema_version"])
        self.assertEqual("wal", readiness["journal_mode"])
        self.assertTrue(readiness["foreign_keys"])
        self.assertNotIn("integrity", readiness)

        health = self.store.health()
        self.assertTrue(health["ok"])
        self.assertEqual(1, health["schema_version"])
        self.assertEqual("wal", health["journal_mode"])
        self.assertTrue(health["foreign_keys"])
        self.assertEqual(("ok",), self.store.integrity_check())
        self.store.close()

        with SQLiteStore(self.path, clock=self.clock) as reopened:
            self.assertEqual(1, reopened.schema_version())
            versions = reopened._connection.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
            self.assertEqual([1], [row[0] for row in versions])

    def test_events_are_tenant_scoped_versioned_and_append_only(self) -> None:
        first = self.store.append_event(
            TENANT,
            "run-1",
            "RUN_STARTED",
            {"goal": "safe deploy"},
            event_id="evt-1",
            expected_stream_version=0,
        )
        second = self.store.append_event(
            TENANT, "run-1", "MOVE_ADDED", {"move": "Q1"}
        )
        self.store.append_event("tenant-b", "run-1", "SECRET", {"hidden": True})
        self.assertEqual([1, 2], [first["stream_version"], second["stream_version"]])
        self.assertEqual(2, len(self.store.list_events(TENANT)))
        self.assertEqual(0, len(self.store.list_events("tenant-c")))
        with self.assertRaises(ConflictError):
            self.store.append_event(
                TENANT,
                "run-1",
                "STALE",
                {},
                expected_stream_version=0,
            )
        with self.assertRaises(ConflictError):
            self.store.append_event(
                TENANT, "other", "DUPLICATE", {}, event_id="evt-1"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.transaction() as connection:
                connection.execute("UPDATE events SET event_type='MUTATED'")
        self.assertEqual("RUN_STARTED", self.store.list_events(TENANT)[0]["event_type"])

    def test_transaction_and_nested_savepoint_rollback(self) -> None:
        with self.assertRaises(RuntimeError):
            with self.store.transaction():
                self.store.append_event(TENANT, "run", "ONE", {})
                with self.store.transaction():
                    self.store.append_event(TENANT, "run", "TWO", {})
                raise RuntimeError("rollback all")
        self.assertEqual([], self.store.list_events(TENANT))

        with self.store.transaction():
            self.store.append_event(TENANT, "run", "KEPT", {})
            with self.assertRaises(ValueError):
                with self.store.transaction():
                    self.store.append_event(TENANT, "run", "DROPPED", {})
                    raise ValueError("rollback savepoint")
        self.assertEqual(["KEPT"], [event["event_type"] for event in self.store.list_events(TENANT)])

    def test_authenticated_evidence_receipt_and_replay_protection(self) -> None:
        payload = {
            "evidence_kind": "tool_invocation",
            "subject_id": "move-7",
            "artifact_uri": "artifact://trace/abc",
            "content_sha256": "1" * 64,
        }
        receipt = self.signer.sign(
            payload,
            purpose="evidence",
            tenant_id=TENANT,
            nonce="evidence-nonce",
        )
        stored = self.store.record_evidence_receipt(TENANT, receipt)
        self.assertEqual("move-7", stored["subject_id"])
        self.assertEqual(receipt, stored["envelope"])
        with self.assertRaises(ReplayDetectedError):
            self.store.record_evidence_receipt(TENANT, receipt)
        with self.assertRaises(InvalidEnvelopeError):
            self.store.record_evidence_receipt("tenant-b", receipt)

        tampered = copy.deepcopy(receipt)
        tampered["payload"]["subject_id"] = "forged"
        with self.assertRaises(InvalidSignatureError):
            self.store.record_evidence_receipt(TENANT, tampered)

    def test_invalid_receipt_payload_rolls_back_nonce_claim(self) -> None:
        receipt = self.signer.sign(
            {"evidence_kind": "trace"},
            purpose="evidence",
            tenant_id=TENANT,
            nonce="retryable-invalid-payload",
        )
        with self.assertRaises(Exception):
            self.store.record_evidence_receipt(TENANT, receipt)
        # Failed persistence must not burn an otherwise authentic receipt.
        count = self.store._connection.execute(
            "SELECT COUNT(*) FROM receipt_nonces WHERE nonce=?",
            ("retryable-invalid-payload",),
        ).fetchone()[0]
        self.assertEqual(0, count)

    def test_authenticated_experience_receipts_are_run_unique_and_tenant_scoped(self) -> None:
        payload = {
            "run_id": "run-1",
            "episode_id": "episode-1",
            "trajectory_hash": "a" * 64,
            "reward": 0.75,
            "policy_version": "candidate-4",
        }
        receipt = self.signer.sign(
            payload,
            purpose="experience",
            tenant_id=TENANT,
            nonce="experience-1",
        )
        stored = self.store.record_experience_receipt(TENANT, receipt)
        self.assertEqual(0.75, stored["reward"])
        self.assertEqual(["episode-1"], [r["episode_id"] for r in self.store.list_experience_receipts(TENANT, run_id="run-1")])
        duplicate_episode = self.signer.sign(
            payload,
            purpose="experience",
            tenant_id=TENANT,
            nonce="experience-2",
        )
        with self.assertRaises(ConflictError):
            self.store.record_experience_receipt(TENANT, duplicate_episode)

    def test_store_refuses_unsigned_receipt_configuration(self) -> None:
        other = SQLiteStore(Path(self.temp.name) / "unsigned.db", clock=self.clock)
        self.addCleanup(other.close)
        receipt = self.signer.sign(
            {
                "evidence_kind": "trace",
                "subject_id": "s",
            },
            purpose="evidence",
            tenant_id=TENANT,
        )
        with self.assertRaises(StoreConfigurationError):
            other.record_evidence_receipt(TENANT, receipt)

    def test_idempotency_claim_conflict_finalization_and_expiry(self) -> None:
        claim = self.store.claim_idempotency(
            TENANT, "commit", "key-1", {"move": "D1"}, ttl_seconds=5
        )
        self.assertTrue(claim.is_new)
        same = self.store.claim_idempotency(
            TENANT, "commit", "key-1", {"move": "D1"}, ttl_seconds=5
        )
        self.assertFalse(same.is_new)
        with self.assertRaises(ConflictError):
            self.store.claim_idempotency(
                TENANT, "commit", "key-1", {"move": "D2"}
            )
        finished = self.store.complete_idempotency(
            TENANT, "commit", "key-1", {"effect_id": "effect-9"}
        )
        self.assertEqual("COMPLETED", finished.status)
        self.assertEqual({"effect_id": "effect-9"}, finished.result)
        self.assertEqual(
            finished,
            self.store.complete_idempotency(
                TENANT, "commit", "key-1", {"effect_id": "effect-9"}
            ),
        )
        with self.assertRaises(ConflictError):
            self.store.fail_idempotency(TENANT, "commit", "key-1", {"error": "late"})

        self.clock.value += 6
        replacement = self.store.claim_idempotency(
            TENANT, "commit", "key-1", {"move": "D2"}
        )
        self.assertTrue(replacement.is_new)

    def test_fenced_leases_block_live_competitor_and_stale_worker(self) -> None:
        first = self.store.acquire_lease(
            TENANT, "run-1", "worker-a", ttl_seconds=10
        )
        self.assertEqual(1, first.fencing_token)
        with self.assertRaises(LeaseUnavailableError):
            self.store.acquire_lease(
                TENANT, "run-1", "worker-b", ttl_seconds=10, now=self.clock.value + 5
            )
        second = self.store.acquire_lease(
            TENANT, "run-1", "worker-b", ttl_seconds=10, now=self.clock.value + 10
        )
        self.assertEqual(2, second.fencing_token)
        with self.assertRaises(ConflictError):
            self.store.renew_lease(
                TENANT,
                "run-1",
                "worker-a",
                first.fencing_token,
                ttl_seconds=10,
            )
        released = self.store.release_lease(
            TENANT, "run-1", "worker-b", second.fencing_token
        )
        self.assertIsNone(released.holder_id)
        third = self.store.acquire_lease(
            TENANT, "run-1", "worker-c", ttl_seconds=10
        )
        self.assertEqual(3, third.fencing_token)

    def test_budget_reservation_is_atomic_integer_and_idempotent(self) -> None:
        created = self.store.create_budget(TENANT, "tokens", 100)
        self.assertEqual(100, created.available_units)
        reserved = self.store.reserve_budget(TENANT, "tokens", "branch-a", 60)
        self.assertEqual((60, 40), (reserved.reserved_units, reserved.available_units))
        same = self.store.reserve_budget(TENANT, "tokens", "branch-a", 60)
        self.assertEqual(reserved, same)
        with self.assertRaises(ConflictError):
            self.store.reserve_budget(TENANT, "tokens", "branch-a", 61)
        with self.assertRaises(BudgetExceededError):
            self.store.reserve_budget(TENANT, "tokens", "branch-b", 41)
        consumed = self.store.consume_budget(TENANT, "tokens", "branch-a")
        self.assertEqual((0, 60, 40), (consumed.reserved_units, consumed.consumed_units, consumed.available_units))
        self.assertEqual(
            consumed, self.store.consume_budget(TENANT, "tokens", "branch-a")
        )
        released = self.store.reserve_budget(TENANT, "tokens", "branch-b", 20)
        self.assertEqual(20, released.reserved_units)
        released = self.store.release_budget(TENANT, "tokens", "branch-b")
        self.assertEqual(40, released.available_units)
        with self.assertRaises(ConflictError):
            self.store.release_budget(TENANT, "tokens", "branch-a")

    def test_competing_process_connections_cannot_overreserve_budget(self) -> None:
        self.store.create_budget(TENANT, "parallel", 10)
        contenders = [
            SQLiteStore(self.path, clock=self.clock),
            SQLiteStore(self.path, clock=self.clock),
        ]
        self.addCleanup(contenders[0].close)
        self.addCleanup(contenders[1].close)
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        outcome_lock = threading.Lock()

        def reserve(store: SQLiteStore, reservation_id: str) -> None:
            barrier.wait()
            try:
                store.reserve_budget(TENANT, "parallel", reservation_id, 7)
                outcome = "reserved"
            except BudgetExceededError:
                outcome = "rejected"
            with outcome_lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=reserve, args=(contenders[0], "worker-a")),
            threading.Thread(target=reserve, args=(contenders[1], "worker-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertCountEqual(["reserved", "rejected"], outcomes)
        snapshot = self.store.get_budget(TENANT, "parallel")
        self.assertEqual((7, 3), (snapshot.reserved_units, snapshot.available_units))

    def test_immutable_artifact_champion_cas_promotion_and_rollback(self) -> None:
        a1 = self.store.register_policy_artifact(
            TENANT,
            "artifact-1",
            "routing",
            "1.0",
            "1" * 64,
            "artifact://policy/1",
            metadata={"suite": "hidden-v3"},
        )
        self.assertEqual("hidden-v3", a1["metadata"]["suite"])
        self.assertEqual(
            a1,
            self.store.register_policy_artifact(
                TENANT,
                "artifact-1",
                "routing",
                "1.0",
                "1" * 64,
                "artifact://policy/1",
                metadata={"suite": "hidden-v3"},
            ),
        )
        with self.assertRaises(ConflictError):
            self.store.register_policy_artifact(
                TENANT,
                "artifact-1",
                "routing",
                "1.0",
                "2" * 64,
                "artifact://policy/changed",
            )
        self.store.register_policy_artifact(
            TENANT,
            "artifact-2",
            "routing",
            "2.0",
            "2" * 64,
            "artifact://policy/2",
        )

        first = self.store.promote_policy(
            TENANT,
            "routing",
            "artifact-1",
            expected_current_artifact_id=None,
            decided_by="promotion-service",
            reason="hidden benchmark passed",
        )
        self.assertEqual((1, None), (first.generation, first.previous_artifact_id))
        with self.assertRaises(ConflictError):
            self.store.promote_policy(
                TENANT,
                "routing",
                "artifact-2",
                expected_current_artifact_id=None,
                decided_by="promotion-service",
                reason="stale decision",
            )
        second = self.store.promote_policy(
            TENANT,
            "routing",
            "artifact-2",
            expected_current_artifact_id="artifact-1",
            decided_by="promotion-service",
            reason="non-inferiority passed",
        )
        self.assertEqual((2, "artifact-1"), (second.generation, second.previous_artifact_id))
        rollback = self.store.promote_policy(
            TENANT,
            "routing",
            "artifact-1",
            expected_current_artifact_id="artifact-2",
            decided_by="incident-commander",
            reason="canary regression rollback",
        )
        self.assertEqual(3, rollback.generation)
        self.assertEqual("artifact-1", self.store.get_champion(TENANT, "routing")["artifact_id"])
        self.assertEqual([1, 2, 3], [p.generation for p in self.store.list_promotion_audit(TENANT, "routing")])
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.transaction() as connection:
                connection.execute("DELETE FROM promotion_audit")

    def test_tenant_namespaces_do_not_collide(self) -> None:
        for tenant in ("tenant-a", "tenant-b"):
            self.store.create_budget(tenant, "same-budget", 10)
            self.store.acquire_lease(tenant, "same-run", "worker", ttl_seconds=5)
            self.store.register_policy_artifact(
                tenant,
                "same-artifact",
                "policy",
                "v1",
                "f" * 64,
                f"artifact://{tenant}/policy",
            )
        self.store.reserve_budget("tenant-a", "same-budget", "r", 7)
        self.assertEqual(3, self.store.get_budget("tenant-a", "same-budget").available_units)
        self.assertEqual(10, self.store.get_budget("tenant-b", "same-budget").available_units)

    def test_backup_is_consistent_and_readable(self) -> None:
        self.store.append_event(TENANT, "run", "CREATED", {"n": 1})
        self.store.register_policy_artifact(
            TENANT,
            "artifact-training",
            "routing",
            "training-v1",
            "a" * 64,
            "artifact://policy/training",
            metadata={"status": "challenger"},
        )
        training = self.store.record_training_run(
            TENANT,
            "training-1",
            "routing",
            "artifact-training",
            "trainer-a",
            7,
            {"accepted": True},
        )
        self.assertEqual(
            training,
            self.store.record_training_run(
                TENANT,
                "training-1",
                "routing",
                "artifact-training",
                "trainer-a",
                7,
                {"accepted": True},
            ),
        )
        with self.assertRaisesRegex(ConflictError, "different immutable provenance"):
            self.store.record_training_run(
                TENANT,
                "training-1",
                "routing",
                "artifact-training",
                "trainer-b",
                8,
                {"accepted": True},
            )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.transaction() as connection:
                connection.execute(
                    "DELETE FROM training_runs WHERE tenant_id=? AND training_id=?",
                    (TENANT, "training-1"),
                )
        backup_path = self.store.backup(Path(self.temp.name) / "backups" / "control.db")
        with SQLiteStore(backup_path, clock=self.clock) as backup:
            self.assertEqual(("ok",), backup.integrity_check())
            self.assertEqual(1, len(backup.list_events(TENANT)))
            restored = backup.list_training_runs(TENANT, "artifact-training")
            self.assertEqual(["training-1"], [run.training_id for run in restored])
            self.assertEqual(
                frozenset({"trainer-a"}),
                backup.training_producers(TENANT, "artifact-training"),
            )

    def test_concurrent_reader_cannot_observe_a_rolled_back_write(self) -> None:
        self.store.create_budget(TENANT, "isolation", 100)
        uncommitted = threading.Event()
        allow_rollback = threading.Event()
        reader_done = threading.Event()
        observed: list[int] = []

        def writer() -> None:
            try:
                with self.store.transaction() as connection:
                    connection.execute(
                        "UPDATE budgets SET consumed_units=7 "
                        "WHERE tenant_id=? AND budget_id=?",
                        (TENANT, "isolation"),
                    )
                    uncommitted.set()
                    allow_rollback.wait(timeout=5)
                    raise RuntimeError("force rollback")
            except RuntimeError:
                pass

        def reader() -> None:
            uncommitted.wait(timeout=5)
            observed.append(
                self.store.get_budget(TENANT, "isolation").consumed_units
            )
            reader_done.set()

        writer_thread = threading.Thread(target=writer)
        reader_thread = threading.Thread(target=reader)
        writer_thread.start()
        self.assertTrue(uncommitted.wait(timeout=5))
        reader_thread.start()
        self.assertFalse(reader_done.wait(timeout=0.1))
        allow_rollback.set()
        writer_thread.join(timeout=5)
        reader_thread.join(timeout=5)
        self.assertEqual([0], observed)


if __name__ == "__main__":
    unittest.main()
