#!/usr/bin/env python3
"""One-command controller acceptance proof on disposable local state."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import shutil
import secrets
import sys
import tempfile

from .backup import create_bundle, restore_bundle
from .config import Principal, Settings
from .control import ControlPlane
from .crypto import ReceiptSigner, ReceiptVerifier
from .engine import PolicyValueModel
from .hidden_benchmark import HiddenBenchmarkClient, HiddenBenchmarkConfig
from .metrics import Metrics
from .store import SQLiteStore

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent


def main() -> int:
    checks: list[tuple[str, bool]] = []
    main_key = secrets.token_bytes(32)
    benchmark_key_bytes = secrets.token_bytes(32)
    backup_key = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory(prefix="agent-tree-rl-acceptance-") as directory:
        root = Path(directory).resolve()
        suite = root / "hidden-suite.json"
        shutil.copyfile(PACKAGE_ROOT / "fixtures" / "sample_policy.json", suite)
        suite.chmod(0o600)
        benchmark_key = root / "benchmark-signing.key"
        benchmark_key.write_bytes(benchmark_key_bytes)
        benchmark_key.chmod(0o600)
        settings = Settings(
            host="127.0.0.1",
            port=0,
            data_dir=root,
            database_path=root / "production.sqlite3",
            receipt_keys_file=root / "unused-keyring.json",
            admin_token_file=root / "unused-token.json",
            benchmark_dir=root,
            require_auth=False,
            allowed_commands=("/bin/echo",),
            allowed_cwd_roots=(root, PROJECT_ROOT),
            default_tenant_budget=20_000,
            require_separation_of_duties=False,
        )
        signer = ReceiptSigner({"main-v1": main_key}, "main-v1")
        verifier = ReceiptVerifier(
            {"main-v1": main_key, "benchmark-v1": benchmark_key_bytes}
        )
        store = SQLiteStore(settings.database_path, receipt_verifier=verifier)
        hidden = HiddenBenchmarkClient(
            HiddenBenchmarkConfig(
                worker_script=PACKAGE_ROOT / "workers" / "benchmark_worker.py",
                benchmark_path=suite,
                signing_key_path=benchmark_key,
                key_id="benchmark-v1",
                candidate_executables=(Path(sys.executable).resolve(),),
                candidate_cwd_roots=(PROJECT_ROOT,),
                python_executable=sys.executable,
            ),
            verifier,
        )
        control = ControlPlane(
            settings=settings,
            store=store,
            signer=signer,
            verifier=verifier,
            metrics=Metrics(),
            hidden_benchmark=hidden,
        )
        principal = Principal(
            "production-proof",
            frozenset({"agent", "operator", "promoter", "auditor"}),
        )

        checks.append(
            (
                "SQLite WAL store is ready and integral",
                bool(control.readiness()["ready"])
                and store.integrity_check() == ("ok",),
            )
        )

        evidence = control.run_evidence(
            principal,
            {
                "command_id": "cmd0",
                "arguments": ["real-probe"],
                "cwd": str(root),
            },
            idempotency_key="verify-evidence-0001",
        )
        checks.append(("real no-shell subprocess evidence is signed and persisted", evidence["outcome"] == "passed"))

        decision = control.run_decision(
            principal,
            {"simulations": 64, "seed": 7},
            idempotency_key="verify-decision-0001",  # gitleaks:allow
        )
        duplicate = control.run_decision(
            principal,
            {"simulations": 64, "seed": 7},
            idempotency_key="verify-decision-0001",  # gitleaks:allow
        )
        checks.append(
            (
                "an exact retry returns one authenticated durable experience",
                decision == duplicate
                and len(store.list_experience_receipts(principal.tenant_id)) == 1,
            )
        )

        cold = control._persist_artifact(
            principal.tenant_id,
            control.POLICY_FAMILY,
            PolicyValueModel(),
            metadata={"status": "bootstrap"},
        )
        store.promote_policy(
            principal.tenant_id,
            control.POLICY_FAMILY,
            cold["artifact_id"],
            expected_current_artifact_id=None,
            decided_by="verify",
            reason="bootstrap",
        )
        champion_benchmark = control.evaluate_hidden_benchmark(
            principal,
            {"challenger_id": cold["artifact_id"]},
            idempotency_key="verify-champion-benchmark-0001",
        )
        trained = control.train_challenger(
            principal,
            {"episodes": 12, "simulations": 128},
            idempotency_key="verify-training-0001",
        )
        checks.append(("transactional challenger passes paired hidden-style gates", bool(trained["promotion_report"]["accepted"])))
        benchmark = control.evaluate_hidden_benchmark(
            principal,
            {"challenger_id": trained["challenger_id"]},
            idempotency_key="verify-benchmark-0001",
        )
        checks.append(
            (
                "hidden benchmark is signed and bound to the immutable challenger",
                benchmark["normalized_score_ppm"] == 1_000_000
                and benchmark["challenger_id"] == trained["challenger_id"]
                and "expected" not in json.dumps(benchmark),
            )
        )
        promoted = control.promote(
            principal,
            trained["challenger_id"],
            {
                "reason": "production acceptance",
                "hidden_benchmark_receipt_id": benchmark["receipt_id"],
                "champion_hidden_benchmark_receipt_id": champion_benchmark["receipt_id"],
            },
            idempotency_key="verify-promotion-0001",
        )
        checks.append(
            (
                "promotion atomically advances champion with audit receipt",
                promoted["promotion"]["artifact_id"] == trained["challenger_id"],
            )
        )

        bundle = create_bundle(
            store,
            root / "artifacts",
            root / "production-backup.atrlb",
            {"backup-v1": backup_key},
            "backup-v1",
        )
        restored_root = root / "fresh-restore"
        restored_root.mkdir()
        restore_result = restore_bundle(
            bundle,
            restored_root / "production.sqlite3",
            restored_root / "artifacts",
            {"backup-v1": backup_key},
        )
        restored_store = SQLiteStore(
            restored_root / "production.sqlite3", receipt_verifier=verifier
        )
        restored_control = ControlPlane(
            settings=replace(
                settings,
                data_dir=restored_root,
                database_path=restored_root / "production.sqlite3",
                allowed_cwd_roots=(restored_root, PROJECT_ROOT),
            ),
            store=restored_store,
            signer=signer,
            verifier=verifier,
            metrics=Metrics(),
            hidden_benchmark=hidden,
        )
        restored_champion = restored_control.get_champion(
            principal, control.POLICY_FAMILY
        )["champion"]
        restored_control._load_artifact(principal.tenant_id, cold["artifact_id"])
        restored_control._load_artifact(principal.tenant_id, trained["challenger_id"])
        checks.append(
            (
                "authenticated bundle restores champion and rollback objects into fresh state",
                restore_result["artifacts"] == 2
                and restored_champion["artifact_id"] == trained["challenger_id"],
            )
        )
        restored_store.close()

        store.close()
        store = SQLiteStore(settings.database_path, receipt_verifier=verifier)
        restarted = ControlPlane(
            settings=settings,
            store=store,
            signer=signer,
            verifier=verifier,
            metrics=Metrics(),
            hidden_benchmark=hidden,
        )
        champion = restarted.get_champion(principal, control.POLICY_FAMILY)["champion"]
        checks.append(("restart preserves champion and receipt state", champion["artifact_id"] == trained["challenger_id"]))
        rollback = restarted.rollback(
            principal,
            control.POLICY_FAMILY,
            {"reason": "reference rollback drill"},
            idempotency_key="verify-rollback-0001",
        )
        checks.append(("rollback creates a new audited generation", rollback["promotion"]["artifact_id"] == cold["artifact_id"]))
        other = Principal("other-tenant", frozenset({"auditor"}))
        checks.append(("tenant namespace blocks champion disclosure", restarted.get_champion(other, control.POLICY_FAMILY)["champion"] is None))
        checks.append(("audit stream records operational lifecycle", len(restarted.audit(principal, after=0, limit=100)["events"]) >= 4))
        store.close()

    print("AGENT TREE RL — CONTROLLER ACCEPTANCE")
    failed = []
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
        if not passed:
            failed.append(name)
    print(f"\n{len(checks) - len(failed)}/{len(checks)} controller gates passed")
    if failed:
        print("Failed: " + "; ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
