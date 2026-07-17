from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from agent_tree_rl.engine import PolicyValueModel
from agent_tree_rl.backup import BackupError, create_bundle, restore_bundle
import agent_tree_rl.backup as backup_module
from agent_tree_rl.config import Principal, Settings
from agent_tree_rl.control import ControlPlane
from agent_tree_rl.crypto import ReceiptSigner, ReceiptVerifier
from agent_tree_rl.metrics import Metrics
from agent_tree_rl.store import SQLiteStore


MAIN_KEY = b"backup-test-main-receipt-key-material-32-bytes"
BACKUP_KEY = b"backup-test-separate-auth-key-material-32-bytes"


class BackupBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.verifier = ReceiptVerifier({"main": MAIN_KEY})
        self.signer = ReceiptSigner({"main": MAIN_KEY}, "main")
        self.settings = Settings(
            host="127.0.0.1",
            port=0,
            data_dir=self.source,
            database_path=self.source / "state.sqlite3",
            receipt_keys_file=self.source / "unused",
            admin_token_file=self.source / "unused",
            benchmark_dir=self.source,
            require_auth=False,
            allowed_commands=("/bin/echo",),
            allowed_cwd_roots=(self.source,),
        )
        self.store = SQLiteStore(
            self.settings.database_path, receipt_verifier=self.verifier
        )
        self.control = ControlPlane(
            settings=self.settings,
            store=self.store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=Metrics(),
        )
        cold = self.control._persist_artifact(
            "tenant-a", self.control.POLICY_FAMILY, PolicyValueModel(), metadata={}
        )
        self.store.promote_policy(
            "tenant-a",
            self.control.POLICY_FAMILY,
            cold["artifact_id"],
            expected_current_artifact_id=None,
            decided_by="test",
            reason="bootstrap",
        )
        trained_model = self.control.learner.train_challenger(PolicyValueModel())
        trained = self.control._persist_artifact(
            "tenant-a", self.control.POLICY_FAMILY, trained_model, metadata={}
        )
        self.store.record_training_run(
            "tenant-a",
            "backup-training",
            self.control.POLICY_FAMILY,
            trained["artifact_id"],
            "test-trainer",
            1,
            {"accepted": True},
        )
        self.store.promote_policy(
            "tenant-a",
            self.control.POLICY_FAMILY,
            trained["artifact_id"],
            expected_current_artifact_id=cold["artifact_id"],
            decided_by="test",
            reason="promote",
        )
        self.cold_id = cold["artifact_id"]
        self.trained_id = trained["artifact_id"]
        (self.source / "api-tokens.json").write_text("SECRET-SENTINEL")
        self.bundle = self.root / "state.atrlb"

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _create(self) -> Path:
        return create_bundle(
            self.store,
            self.source / "artifacts",
            self.bundle,
            {"backup-v1": BACKUP_KEY},
            "backup-v1",
        )

    def test_bundle_round_trips_to_new_root_and_preserves_rollback(self) -> None:
        self._create()
        with zipfile.ZipFile(self.bundle) as archive:
            names = archive.namelist()
            raw = b"".join(archive.read(name) for name in names)
        self.assertIn("manifest.json", names)
        self.assertIn("state.sqlite3", names)
        self.assertNotIn(b"SECRET-SENTINEL", raw)
        self.assertFalse(any("token" in name or "benchmark" in name for name in names))

        self.store.close()
        shutil.rmtree(self.source)
        destination = self.root / "restored"
        destination.mkdir()
        result = restore_bundle(
            self.bundle,
            destination / "state.sqlite3",
            destination / "artifacts",
            {"backup-v1": BACKUP_KEY},
        )
        self.assertEqual(2, result["artifacts"])
        restored_store = SQLiteStore(
            destination / "state.sqlite3", receipt_verifier=self.verifier
        )
        restored_settings = Settings(
            **{
                **self.settings.__dict__,
                "data_dir": destination,
                "database_path": destination / "state.sqlite3",
                "allowed_cwd_roots": (destination,),
            }
        )
        restored = ControlPlane(
            settings=restored_settings,
            store=restored_store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=Metrics(),
        )
        principal = Principal(
            "tenant-a", frozenset({"agent", "operator", "promoter", "auditor"})
        )
        try:
            champion = restored.get_champion(
                principal, restored.POLICY_FAMILY
            )["champion"]
            self.assertEqual(self.trained_id, champion["artifact_id"])
            training_runs = restored_store.list_training_runs(
                "tenant-a", self.trained_id
            )
            self.assertEqual(
                ["backup-training"],
                [run.training_id for run in training_runs],
            )
            decision = restored.run_decision(
                principal,
                {"simulations": 16, "seed": 7},
                idempotency_key="restored-decision-0001",
            )
            self.assertEqual(champion["version"], decision["model_version"])
            rollback = restored.rollback(
                principal,
                restored.POLICY_FAMILY,
                {"reason": "restore drill"},
                idempotency_key="restored-rollback-0001",
            )
            self.assertEqual(self.cold_id, rollback["promotion"]["artifact_id"])
        finally:
            restored_store.close()

    def test_tampered_manifest_wrong_key_and_extra_member_are_rejected(self) -> None:
        self._create()
        destination = self.root / "restore"
        destination.mkdir()
        with self.assertRaisesRegex(BackupError, "authentication failed"):
            restore_bundle(
                self.bundle,
                destination / "wrong.sqlite3",
                destination / "wrong-artifacts",
                {"backup-v1": b"x" * 32},
            )

        altered = self.root / "extra.atrlb"
        with zipfile.ZipFile(self.bundle) as source, zipfile.ZipFile(
            altered, "w", compression=zipfile.ZIP_STORED
        ) as target:
            for info in source.infolist():
                target.writestr(info, source.read(info.filename))
            target.writestr("../escape", b"no")
        with self.assertRaisesRegex(BackupError, "unsafe bundle member"):
            restore_bundle(
                altered,
                destination / "extra.sqlite3",
                destination / "extra-artifacts",
                {"backup-v1": BACKUP_KEY},
            )

    def test_restore_refuses_existing_state_and_backup_never_overwrites(self) -> None:
        self._create()
        with self.assertRaises(FileExistsError):
            self._create()
        destination = self.root / "occupied"
        destination.mkdir()
        database = destination / "state.sqlite3"
        database.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            restore_bundle(
                self.bundle,
                database,
                destination / "artifacts",
                {"backup-v1": BACKUP_KEY},
            )
        self.assertEqual(b"keep", database.read_bytes())

    def test_empty_artifact_set_round_trips(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        empty_store = SQLiteStore(empty / "state.sqlite3")
        empty_bundle = self.root / "empty.atrlb"
        try:
            create_bundle(
                empty_store,
                empty / "artifacts",
                empty_bundle,
                {"backup-v1": BACKUP_KEY},
                "backup-v1",
            )
        finally:
            empty_store.close()
        restored = self.root / "empty-restored"
        restored.mkdir()
        result = restore_bundle(
            empty_bundle,
            restored / "state.sqlite3",
            restored / "artifacts",
            {"backup-v1": BACKUP_KEY},
        )
        self.assertEqual(0, result["artifacts"])
        self.assertTrue((restored / "artifacts").is_dir())

    def test_interrupted_install_resumes_from_recovery_marker(self) -> None:
        self._create()
        destination = self.root / "interrupted"
        destination.mkdir()
        database = destination / "state.sqlite3"
        artifacts = destination / "artifacts"
        real_replace = backup_module.os.replace

        class SimulatedCrash(BaseException):
            pass

        def crash_before_database(source: object, target: object) -> None:
            if Path(target) == database:
                raise SimulatedCrash()
            real_replace(source, target)

        with patch.object(backup_module.os, "replace", side_effect=crash_before_database):
            with self.assertRaises(SimulatedCrash):
                restore_bundle(
                    self.bundle,
                    database,
                    artifacts,
                    {"backup-v1": BACKUP_KEY},
                )
        self.assertTrue(artifacts.is_dir())
        self.assertFalse(database.exists())
        marker = destination / backup_module.RESTORE_MARKER
        self.assertTrue(marker.is_file())

        original_marker = marker.read_bytes()
        forged = json.loads(original_marker)
        signature = forged["authentication"]["signature"]
        forged["authentication"]["signature"] = (
            ("A" if signature[-1] != "A" else "B") + signature[:-1]
        )
        marker.write_text(json.dumps(forged), encoding="utf-8")
        with self.assertRaisesRegex(BackupError, "authentication"):
            restore_bundle(
                self.bundle,
                database,
                artifacts,
                {"backup-v1": BACKUP_KEY},
            )
        marker.write_bytes(original_marker)

        installed_object = next(artifacts.rglob("*.json"))
        relative_object = installed_object.relative_to(artifacts)
        installed_object.write_bytes(b"corrupt-policy-object")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            restore_bundle(
                self.bundle,
                database,
                artifacts,
                {"backup-v1": BACKUP_KEY},
            )
        shutil.copyfile(
            self.source / "artifacts" / relative_object,
            installed_object,
        )

        result = restore_bundle(
            self.bundle,
            database,
            artifacts,
            {"backup-v1": BACKUP_KEY},
        )
        self.assertTrue(result["resumed"])
        self.assertTrue(database.is_file())
        self.assertFalse((destination / backup_module.RESTORE_MARKER).exists())
        restored_store = SQLiteStore(database, receipt_verifier=self.verifier)
        restored = ControlPlane(
            settings=Settings(
                **{
                    **self.settings.__dict__,
                    "data_dir": destination,
                    "database_path": database,
                    "allowed_cwd_roots": (destination,),
                }
            ),
            store=restored_store,
            signer=self.signer,
            verifier=self.verifier,
            metrics=Metrics(),
        )
        principal = Principal(
            "tenant-a", frozenset({"agent", "promoter"}), "restore-drill"
        )
        try:
            decision = restored.run_decision(
                principal,
                {"simulations": 8},
                idempotency_key="resumed-decision-key",
            )
            self.assertEqual(self.trained_id, restored.get_champion(
                principal, restored.POLICY_FAMILY
            )["champion"]["artifact_id"])
            self.assertTrue(decision["feasible"])
            rollback = restored.rollback(
                principal,
                restored.POLICY_FAMILY,
                {"reason": "resumed restore drill"},
                idempotency_key="resumed-rollback-key",
            )
            self.assertEqual(self.cold_id, rollback["promotion"]["artifact_id"])
        finally:
            restored_store.close()

    def test_creation_and_restore_enforce_cumulative_size_cap(self) -> None:
        too_small = self.root / "too-small.atrlb"
        with patch.object(backup_module, "MAX_BUNDLE_CONTENT_BYTES", 1):
            with self.assertRaisesRegex(BackupError, "cumulative size cap"):
                create_bundle(
                    self.store,
                    self.source / "artifacts",
                    too_small,
                    {"backup-v1": BACKUP_KEY},
                    "backup-v1",
                )
        self.assertFalse(too_small.exists())

        self._create()
        destination = self.root / "capped-restore"
        destination.mkdir()
        with patch.object(backup_module, "MAX_BUNDLE_CONTENT_BYTES", 1):
            with self.assertRaisesRegex(BackupError, "cumulative size cap"):
                restore_bundle(
                    self.bundle,
                    destination / "state.sqlite3",
                    destination / "artifacts",
                    {"backup-v1": BACKUP_KEY},
                )

        with zipfile.ZipFile(self.bundle) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        exact_content_size = manifest["database"]["size_bytes"] + sum(
            item["size_bytes"] for item in manifest["objects"]
        )
        exact_bundle = self.root / "exact-cap.atrlb"
        exact_destination = self.root / "exact-cap-restore"
        exact_destination.mkdir()
        with patch.object(
            backup_module, "MAX_BUNDLE_CONTENT_BYTES", exact_content_size
        ):
            create_bundle(
                self.store,
                self.source / "artifacts",
                exact_bundle,
                {"backup-v1": BACKUP_KEY},
                "backup-v1",
            )
            restored = restore_bundle(
                exact_bundle,
                exact_destination / "state.sqlite3",
                exact_destination / "artifacts",
                {"backup-v1": BACKUP_KEY},
            )
        self.assertEqual(2, restored["artifacts"])

    def test_restore_reads_every_zip_member_with_an_explicit_bound(self) -> None:
        self._create()
        destination = self.root / "bounded-read"
        destination.mkdir()
        original_read = zipfile.ZipExtFile.read
        requested_sizes: list[int] = []

        def tracked_read(handle: zipfile.ZipExtFile, size: int = -1) -> bytes:
            requested_sizes.append(size)
            if size < 0:
                raise AssertionError("unbounded ZIP member read")
            return original_read(handle, size)

        with patch.object(zipfile.ZipExtFile, "read", new=tracked_read):
            restore_bundle(
                self.bundle,
                destination / "state.sqlite3",
                destination / "artifacts",
                {"backup-v1": BACKUP_KEY},
            )
        self.assertTrue(requested_sizes)
        self.assertTrue(all(0 <= size <= backup_module.MAX_MANIFEST_BYTES + 1 for size in requested_sizes))

    def test_post_verification_source_substitution_cannot_enter_bundle(self) -> None:
        real_verify = backup_module.read_verified_policy
        replacement = b"SECRET-POST-VERIFY-SUBSTITUTION"

        def swap_after_verification(path: Path, digest: str) -> bytes:
            verified = real_verify(path, digest)
            path.write_bytes(replacement)
            return verified

        with patch.object(
            backup_module,
            "read_verified_policy",
            side_effect=swap_after_verification,
        ):
            self._create()
        with zipfile.ZipFile(self.bundle) as archive:
            object_data = b"".join(
                archive.read(name)
                for name in archive.namelist()
                if name.startswith("objects/")
            )
        self.assertNotIn(replacement, object_data)


if __name__ == "__main__":
    unittest.main()
