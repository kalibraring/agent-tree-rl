"""Production orchestration: auth-scoped work, receipts, budgets and promotion."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import tempfile
from threading import Event
import time
import sys
from typing import Any, Callable
import uuid

from . import __version__
from .engine import PUCTSearch, PolicyValueModel, default_benchmark, default_scenario
from .config import Principal, Settings
from .artifacts import (
    policy_artifact_path,
    policy_artifact_uri,
    read_verified_policy,
    resolve_policy_artifact,
)
from .crypto import (
    ReceiptError,
    ReceiptSigner,
    ReceiptVerifier,
    canonical_json_bytes,
    sha256_hex,
)
from .evidence import EvidenceRunner, RunnerPolicy
from .hidden_benchmark import (
    HiddenBenchmarkClient,
    candidate_fingerprint,
    opaque_suite_digest,
)
from .learner import OfflineLearner
from .metrics import Metrics
from .process_registry import ActiveProcessRegistry, CancellationReport
from .serde import model_from_payload, model_to_payload, search_result_to_experience
from .store import (
    ConflictError,
    NotFoundError,
    SQLiteStore,
)


class ControlPlane:
    POLICY_FAMILY = "agent-decision-routing"

    def __init__(
        self,
        *,
        settings: Settings,
        store: SQLiteStore,
        signer: ReceiptSigner,
        verifier: ReceiptVerifier,
        metrics: Metrics,
        hidden_benchmark: HiddenBenchmarkClient | None = None,
        process_registry: ActiveProcessRegistry | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.signer = signer
        self.verifier = verifier
        self.metrics = metrics
        self.hidden_benchmark = hidden_benchmark
        self.process_registry = (
            process_registry
            or (
                hidden_benchmark.process_registry
                if hidden_benchmark is not None
                else ActiveProcessRegistry()
            )
        )
        if (
            hidden_benchmark is not None
            and hidden_benchmark.process_registry is not self.process_registry
        ):
            raise ValueError("hidden benchmark must share the service process registry")
        self._draining = Event()
        self.learner = OfflineLearner(family=self.POLICY_FAMILY)
        commands = {
            f"cmd{index}": command
            for index, command in enumerate(settings.allowed_commands)
        }
        self.runner_policy = (
            RunnerPolicy(
                allowed_executables=commands,
                allowed_cwd_roots=settings.allowed_cwd_roots,
                timeout_seconds=30,
                output_cap_bytes=256 * 1024,
                stdin_cap_bytes=1024 * 1024,
                allowed_environment=frozenset(),
                fixed_environment={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PATH": f"{Path(sys.executable).resolve().parent}:/usr/bin:/bin",
                },
            )
            if commands and settings.allowed_cwd_roots
            else None
        )
        self.artifact_dir = settings.data_dir / "artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True, mode=0o750)

    def health(self) -> dict[str, object]:
        return {
            "status": "draining" if self._draining.is_set() else "ok",
            "service": "agent-tree-rl",
            "version": __version__,
        }

    def begin_draining(self) -> bool:
        """Make readiness fail before the HTTP server stops admitting work."""

        changed = not self._draining.is_set()
        self._draining.set()
        return changed

    def cancel_active_processes(
        self, *, timeout_seconds: float
    ) -> CancellationReport:
        """Cancel and reap every service-owned subprocess group."""

        return self.process_registry.cancel_all(timeout_seconds=timeout_seconds)

    def readiness(self) -> dict[str, object]:
        storage = self.store.readiness_check()
        ready = (
            not self._draining.is_set()
            and
            bool(storage.get("ok"))
            and self.runner_policy is not None
            and self.hidden_benchmark is not None
        )
        return {
            "ready": ready,
            "lifecycle": "draining" if self._draining.is_set() else "ready",
            "accepting_work": not self._draining.is_set(),
            "storage": storage,
            "evidence_runner": self.runner_policy is not None,
            "hidden_benchmark": self.hidden_benchmark is not None,
        }

    def run_decision(
        self, principal: Principal, request: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        _require_allowed_fields(request, {"simulations", "seed", "family"})

        def operation() -> dict[str, Any]:
            simulations = _bounded_int(request, "simulations", 128, 8, 4096)
            seed = _bounded_int(request, "seed", 7, 0, 2**31 - 1)
            family = _bounded_text(request, "family", self.POLICY_FAMILY, 128)
            if family != self.POLICY_FAMILY:
                raise ValueError("unregistered policy family")
            run_id = uuid.uuid4().hex
            reservation = f"decision-{run_id}"
            budget_id = "api-compute"
            self.store.create_budget(
                principal.tenant_id, budget_id, self.settings.default_tenant_budget
            )
            self.store.reserve_budget(
                principal.tenant_id, budget_id, reservation, simulations
            )
            try:
                model = self._champion_model(principal.tenant_id, family)
                scenario = default_scenario()
                benchmark = default_benchmark(scenario)
                result = PUCTSearch(
                    scenario, benchmark, model, seed=seed
                ).run(simulations=simulations)
                experience = search_result_to_experience(
                    result,
                    tenant_id=principal.tenant_id,
                    family=family,
                    run_id=run_id,
                )
                trajectory_hash = hashlib.sha256(
                    canonical_json_bytes(experience["trajectory"])
                ).hexdigest()
                envelope = self.signer.sign(
                    {
                        "run_id": run_id,
                        "episode_id": run_id,
                        "trajectory_hash": trajectory_hash,
                        "reward": result.score.reward,
                        "experience": experience,
                    },
                    purpose="experience",
                    tenant_id=principal.tenant_id,
                    ttl_seconds=None,
                )
                with self.store.transaction():
                    stored = self.store.record_experience_receipt(
                        principal.tenant_id, envelope
                    )
                    self.store.append_event(
                        principal.tenant_id,
                        f"run:{run_id}",
                        "DECISION_COMPLETED",
                        {
                            "family": family,
                            "requested_by": principal.subject_id,
                            "reward": result.score.reward,
                            "feasible": result.score.feasible,
                            "abstained": result.abstained,
                            "experience_receipt_id": stored["receipt_id"],
                        },
                    )
                    self.store.consume_budget(
                        principal.tenant_id, budget_id, reservation
                    )
                    response = {
                        "run_id": run_id,
                        "family": family,
                        "model_version": result.model_version,
                        "trajectory": [move.id for move in result.trajectory],
                        "reward": result.score.reward,
                        "feasible": result.score.feasible,
                        "abstained": result.abstained,
                        "benchmark_evaluations": result.benchmark_evaluations,
                        "experience_receipt_id": stored["receipt_id"],
                    }
                    self._complete_atomic(
                        principal, "decision", idempotency_key, response
                    )
                self.metrics.increment(
                    "decisions_total",
                    tenant=principal.tenant_id,
                    outcome="abstained" if result.abstained else "committed",
                )
                return response
            except Exception:
                self.store.release_budget(
                    principal.tenant_id, budget_id, reservation
                )
                raise

        return self._idempotent(principal, "decision", idempotency_key, request, operation)

    def run_evidence(
        self, principal: Principal, request: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        _require_allowed_fields(
            request,
            {"command_id", "arguments", "cwd", "artifacts"},
        )

        def operation() -> dict[str, Any]:
            if self.runner_policy is None:
                raise ValueError("evidence runner is not configured")
            command_id = request.get("command_id")
            arguments = request.get("arguments", [])
            cwd = request.get("cwd")
            if (
                not isinstance(command_id, str)
                or command_id not in {
                    f"cmd{index}" for index in range(len(self.settings.allowed_commands))
                }
                or not isinstance(arguments, list)
                or len(arguments) > 64
                or not all(
                    isinstance(value, str)
                    and value
                    and "\x00" not in value
                    and len(value.encode("utf-8")) <= 4096
                    for value in arguments
                )
                or not isinstance(cwd, str)
                or not cwd
                or "\x00" in cwd
                or len(cwd.encode("utf-8")) > 4096
            ):
                raise ValueError(
                    "allowlisted command_id, bounded arguments list, and cwd are required"
                )
            artifacts = request.get("artifacts", [])
            if (
                not isinstance(artifacts, list)
                or len(artifacts) > 64
                or not all(
                    isinstance(value, str)
                    and value
                    and "\x00" not in value
                    and len(value.encode("utf-8")) <= 4096
                    for value in artifacts
                )
            ):
                raise ValueError("artifacts must be a bounded list of paths")
            runner = EvidenceRunner(
                self.runner_policy,
                self.signer,
                tenant_id=principal.tenant_id,
                process_registry=self.process_registry,
            )
            result = runner.run(
                [command_id, *arguments],
                cwd=cwd,
                artifacts=[str(value) for value in artifacts],
                correlation_id=idempotency_key,
            )
            raw_payload = self.verifier.verify(
                result.receipt,
                expected_purpose="subprocess-evidence",
                expected_tenant_id=principal.tenant_id,
            )
            if not isinstance(raw_payload, dict):
                raise ValueError("subprocess evidence receipt payload must be an object")
            subject_id = str(raw_payload["receipt_id"])
            normalized = self.signer.sign(
                {
                    "evidence_kind": "subprocess",
                    "subject_id": subject_id,
                    "artifact_uri": f"receipt://subprocess/{subject_id}",
                    "content_sha256": sha256_hex(result.receipt),
                    "outcome": raw_payload.get("outcome"),
                    "attestation": result.receipt,
                },
                purpose="evidence",
                tenant_id=principal.tenant_id,
                ttl_seconds=None,
            )
            with self.store.transaction():
                stored = self.store.record_evidence_receipt(
                    principal.tenant_id, normalized
                )
                self.store.append_event(
                    principal.tenant_id,
                    f"evidence:{subject_id}",
                    "EVIDENCE_RECORDED",
                    {
                        "receipt_id": stored["receipt_id"],
                        "requested_by": principal.subject_id,
                        "outcome": raw_payload.get("outcome"),
                    },
                )
                response = {
                    "receipt_id": stored["receipt_id"],
                    "subject_id": subject_id,
                    "outcome": raw_payload.get("outcome"),
                    "duration_ms": raw_payload.get("duration_ms"),
                    "output": raw_payload.get("output"),
                }
                self._complete_atomic(
                    principal, "evidence", idempotency_key, response
                )
            self.metrics.increment(
                "evidence_runs_total",
                tenant=principal.tenant_id,
                outcome=str(raw_payload.get("outcome")),
            )
            return response

        return self._idempotent(principal, "evidence", idempotency_key, request, operation)

    def evaluate_hidden_benchmark(
        self, principal: Principal, request: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        _require_allowed_fields(request, {"challenger_id"})

        def operation() -> dict[str, Any]:
            if self.hidden_benchmark is None:
                raise ValueError("hidden benchmark worker is not configured")
            challenger_id = request.get("challenger_id")
            if (
                not isinstance(challenger_id, str)
                or not challenger_id
                or "\x00" in challenger_id
                or len(challenger_id.encode("utf-8")) > 256
            ):
                raise ValueError("challenger_id is required")
            # Load and hash-check before the worker sees the artifact. The worker
            # fingerprint also includes this exact file, so a receipt cannot be
            # detached and reused to promote a different challenger.
            self._load_artifact(principal.tenant_id, challenger_id)
            artifact = self.store.get_policy_artifact(
                principal.tenant_id, challenger_id
            )
            artifact_path = resolve_policy_artifact(
                self.artifact_dir,
                principal.tenant_id,
                str(artifact["content_sha256"]),
                str(artifact["artifact_uri"]),
            ).resolve(strict=True)
            candidate_script = (
                Path(__file__).resolve().parent / "workers" / "policy_candidate.py"
            )
            argv = [
                str(self.hidden_benchmark.python_executable),
                str(candidate_script),
                str(artifact_path),
            ]
            cwd = Path(__file__).resolve().parent.parent
            suite_digest = opaque_suite_digest(self.hidden_benchmark.benchmark_path)
            quota_window = (
                int(time.time())
                // self.settings.hidden_benchmark_quota_window_seconds
            )
            budget_id = (
                f"hidden-benchmark:{challenger_id}:{suite_digest[:16]}:"
                f"{quota_window}"
            )
            reservation = f"attempt:{idempotency_key}"
            self.store.create_budget(
                principal.tenant_id,
                budget_id,
                self.settings.hidden_benchmark_attempt_limit,
            )
            self.store.reserve_budget(
                principal.tenant_id, budget_id, reservation, 1
            )
            try:
                aggregate = self.hidden_benchmark.run(
                    argv,
                    candidate_cwd=cwd,
                    nonce=idempotency_key,
                )
                payload = aggregate["payload"]
                normalized = self.signer.sign(
                    {
                        "evidence_kind": "hidden-benchmark",
                        "subject_id": str(payload["candidate"]["fingerprint_sha256"]),
                        "artifact_uri": "benchmark://hidden/aggregate",
                        "content_sha256": sha256_hex(aggregate),
                        "policy_artifact_id": challenger_id,
                        "policy_content_sha256": artifact["content_sha256"],
                        "aggregate": aggregate,
                    },
                    purpose="evidence",
                    tenant_id=principal.tenant_id,
                    ttl_seconds=None,
                )
                result = payload["result"]
                with self.store.transaction():
                    self.store.consume_budget(
                        principal.tenant_id, budget_id, reservation
                    )
                    stored = self.store.record_evidence_receipt(
                        principal.tenant_id, normalized
                    )
                    self.store.append_event(
                        principal.tenant_id,
                        f"policy:{challenger_id}",
                        "HIDDEN_BENCHMARK_COMPLETED",
                        {
                            "receipt_id": stored["receipt_id"],
                            "requested_by": principal.subject_id,
                            "suite_digest": payload["benchmark"]["suite_sha256"],
                            "normalized_score_ppm": result["normalized_score_ppm"],
                        },
                    )
                    response = {
                        "receipt_id": stored["receipt_id"],
                        "challenger_id": challenger_id,
                        "suite_digest": payload["benchmark"]["suite_sha256"],
                        "candidate_fingerprint": payload["candidate"]["fingerprint_sha256"],
                        "passed": result["passed"],
                        "failed": result["failed"],
                        "total": result["total"],
                        "normalized_score_ppm": result["normalized_score_ppm"],
                    }
                    self._complete_atomic(
                        principal, "hidden-benchmark", idempotency_key, response
                    )
            except Exception:
                try:
                    self.store.release_budget(
                        principal.tenant_id, budget_id, reservation
                    )
                except ConflictError:
                    pass
                raise
            self.metrics.increment(
                "hidden_benchmarks_total", tenant=principal.tenant_id
            )
            return response

        return self._idempotent(principal, "hidden-benchmark", idempotency_key, request, operation)

    def train_challenger(
        self, principal: Principal, request: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        _require_allowed_fields(request, {"family", "episodes", "simulations"})

        def operation() -> dict[str, Any]:
            family = _bounded_text(request, "family", self.POLICY_FAMILY, 128)
            if family != self.POLICY_FAMILY:
                raise ValueError("unregistered policy family")
            episodes = _bounded_int(request, "episodes", 12, 1, 1000)
            simulations = _bounded_int(request, "simulations", 128, 8, 4096)
            holder = uuid.uuid4().hex
            reservation = f"training-{holder}"
            budget_id = "api-compute"
            units = episodes * simulations
            self.store.create_budget(
                principal.tenant_id, budget_id, self.settings.default_tenant_budget
            )
            self.store.reserve_budget(
                principal.tenant_id, budget_id, reservation, units
            )
            lease = None
            lease_ttl = max(
                self.settings.lease_seconds, min(3600, episodes * 2)
            )
            try:
                lease = self.store.acquire_lease(
                    principal.tenant_id,
                    f"train:{family}",
                    holder,
                    ttl_seconds=lease_ttl,
                )
                champion = self._champion_model(principal.tenant_id, family)
                challenger = self.learner.train_challenger(
                    champion,
                    episodes=episodes,
                    simulations=simulations,
                    heartbeat=lambda _: self.store.renew_lease(
                        principal.tenant_id,
                        f"train:{family}",
                        holder,
                        lease.fencing_token,
                        ttl_seconds=lease_ttl,
                    ),
                )
                report = self.learner.promotion_report(champion, challenger)
                report_payload = report.to_payload()
                with self.store.transaction():
                    # Final renewal is the fencing check. No competing writer
                    # can take the lease between this check and artifact commit.
                    self.store.renew_lease(
                        principal.tenant_id,
                        f"train:{family}",
                        holder,
                        lease.fencing_token,
                        ttl_seconds=lease_ttl,
                    )
                    artifact = self._persist_artifact(
                        principal.tenant_id,
                        family,
                        challenger,
                        metadata={"status": "challenger"},
                    )
                    self.store.record_training_run(
                        principal.tenant_id,
                        idempotency_key,
                        family,
                        artifact["artifact_id"],
                        principal.subject_id,
                        lease.fencing_token,
                        report_payload,
                    )
                    self.store.append_event(
                        principal.tenant_id,
                        f"policy:{family}",
                        "CHALLENGER_TRAINED",
                        {
                            "artifact_id": artifact["artifact_id"],
                            "training_id": idempotency_key,
                            "trained_by": principal.subject_id,
                            "lease_fencing_token": lease.fencing_token,
                            "promotion_report": report_payload,
                            "accepted_by_offline_gate": report.accepted,
                        },
                    )
                    self.store.consume_budget(
                        principal.tenant_id, budget_id, reservation
                    )
                    response = {
                        "challenger_id": artifact["artifact_id"],
                        "training_id": idempotency_key,
                        "model_version": challenger.model_version,
                        "promotion_report": report_payload,
                    }
                    self._complete_atomic(
                        principal, "train", idempotency_key, response
                    )
                return response
            finally:
                try:
                    budget = self.store.get_budget(principal.tenant_id, budget_id)
                    if budget.reserved_units:
                        self.store.release_budget(
                            principal.tenant_id, budget_id, reservation
                        )
                except (ConflictError, NotFoundError):
                    pass
                if lease is not None:
                    try:
                        self.store.release_lease(
                            principal.tenant_id,
                            f"train:{family}",
                            holder,
                            lease.fencing_token,
                        )
                    except ConflictError:
                        pass

        return self._idempotent(principal, "train", idempotency_key, request, operation)

    def promote(
        self,
        principal: Principal,
        challenger_id: str,
        request: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _require_allowed_fields(
            request,
            {
                "family",
                "hidden_benchmark_receipt_id",
                "champion_hidden_benchmark_receipt_id",
                "reason",
            },
        )

        def operation() -> dict[str, Any]:
            family = _bounded_text(request, "family", self.POLICY_FAMILY, 128)
            reason = _bounded_text(
                request,
                "reason",
                "passed controlled promotion gates",
                2000,
            )
            artifact_row = self.store.get_policy_artifact(
                principal.tenant_id, challenger_id
            )
            if artifact_row["policy_name"] != family:
                raise ConflictError("challenger belongs to a different policy")
            if self.settings.require_separation_of_duties:
                producers = self.store.training_producers(
                    principal.tenant_id, challenger_id
                )
                if not producers:
                    raise ConflictError("challenger producer identity is missing")
                if principal.subject_id in producers:
                    raise ConflictError(
                        "challenger producer and promoter must be different subjects"
                    )
            candidate_payload = self._load_artifact(principal.tenant_id, challenger_id)
            challenger = model_from_payload(candidate_payload)
            champion_row = self.store.get_champion(principal.tenant_id, family)
            champion = self._champion_model(principal.tenant_id, family)
            report = self.learner.promotion_report(champion, challenger)
            if not report.accepted:
                raise ConflictError("challenger failed promotion gates: " + "; ".join(report.reasons))
            benchmark_receipt_id = request.get("hidden_benchmark_receipt_id")
            if not isinstance(benchmark_receipt_id, str) or not benchmark_receipt_id:
                raise ValueError("hidden_benchmark_receipt_id is required")
            hidden_result = self._validate_promotion_benchmark(
                principal.tenant_id,
                challenger_id,
                benchmark_receipt_id,
            )
            champion_hidden_result: dict[str, Any] | None = None
            if champion_row is not None:
                champion_receipt_id = request.get(
                    "champion_hidden_benchmark_receipt_id"
                )
                if not isinstance(champion_receipt_id, str) or not champion_receipt_id:
                    raise ValueError(
                        "champion_hidden_benchmark_receipt_id is required"
                    )
                champion_hidden_result = self._validate_promotion_benchmark(
                    principal.tenant_id,
                    str(champion_row["artifact_id"]),
                    champion_receipt_id,
                    enforce_absolute_threshold=False,
                )
                if (
                    hidden_result["normalized_score_ppm"]
                    < champion_hidden_result["normalized_score_ppm"]
                ):
                    raise ConflictError(
                        "challenger regresses on the paired hidden benchmark"
                    )
            expected = None if champion_row is None else champion_row["artifact_id"]
            with self.store.transaction():
                offline_report_receipt = self._record_promotion_report(
                    principal.tenant_id, challenger_id, report.to_payload()
                )
                promotion = self.store.promote_policy(
                    principal.tenant_id,
                    family,
                    challenger_id,
                    expected_current_artifact_id=expected,
                    decided_by=principal.subject_id,
                    reason=reason,
                    benchmark_receipt_id=benchmark_receipt_id,
                )
                self.store.append_event(
                    principal.tenant_id,
                    f"policy:{family}",
                    "POLICY_PROMOTED",
                    asdict(promotion),
                )
                response = {
                    "promotion": asdict(promotion),
                    "report": report.to_payload(),
                    "hidden_benchmark": hidden_result,
                    "champion_hidden_benchmark": champion_hidden_result,
                    "offline_report_receipt_id": offline_report_receipt,
                }
                self._complete_atomic(
                    principal, "promote", idempotency_key, response
                )
            self.metrics.increment("promotions_total", tenant=principal.tenant_id)
            return response

        payload = {**request, "challenger_id": challenger_id}
        return self._idempotent(principal, "promote", idempotency_key, payload, operation)

    def rollback(
        self,
        principal: Principal,
        family: str,
        request: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _require_allowed_fields(request, {"reason"})

        def operation() -> dict[str, Any]:
            reason = _bounded_text(request, "reason", "operator rollback", 2000)
            current = self.store.get_champion(principal.tenant_id, family)
            if current is None:
                raise NotFoundError("no champion exists")
            current_promotion = self.store.get_promotion_at_generation(
                principal.tenant_id,
                family,
                int(current["generation"]),
            )
            if (
                current_promotion is None
                or current_promotion.artifact_id != current["artifact_id"]
            ):
                raise ConflictError("champion promotion audit is missing or inconsistent")
            previous = current_promotion.previous_artifact_id
            if previous is None:
                raise ConflictError("champion has no rollback target")
            with self.store.transaction():
                promotion = self.store.promote_policy(
                    principal.tenant_id,
                    family,
                    previous,
                    expected_current_artifact_id=current["artifact_id"],
                    decided_by=principal.subject_id,
                    reason=reason,
                )
                self.store.append_event(
                    principal.tenant_id,
                    f"policy:{family}",
                    "POLICY_ROLLED_BACK",
                    asdict(promotion),
                )
                response = {"promotion": asdict(promotion)}
                self._complete_atomic(
                    principal, "rollback", idempotency_key, response
                )
            self.metrics.increment("rollbacks_total", tenant=principal.tenant_id)
            return response

        payload = {**request, "family": family}
        return self._idempotent(principal, "rollback", idempotency_key, payload, operation)

    def get_champion(self, principal: Principal, family: str) -> dict[str, Any]:
        row = self.store.get_champion(principal.tenant_id, family)
        return {"champion": row}

    def audit(self, principal: Principal, *, after: int, limit: int) -> dict[str, Any]:
        return {
            "events": self.store.list_events(
                principal.tenant_id, after_sequence=after, limit=limit
            )
        }

    def _champion_model(self, tenant_id: str, family: str) -> PolicyValueModel:
        champion = self.store.get_champion(tenant_id, family)
        if champion is None:
            return PolicyValueModel()
        return model_from_payload(
            self._load_artifact(tenant_id, str(champion["artifact_id"]))
        )

    def _persist_artifact(
        self,
        tenant_id: str,
        family: str,
        model: PolicyValueModel,
        *,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        payload = model_to_payload(model, family=family)
        encoded = canonical_json_bytes(payload)
        content_hash = hashlib.sha256(encoded).hexdigest()
        artifact_id = "policy-" + content_hash
        path = policy_artifact_path(self.artifact_dir, tenant_id, content_hash)
        tenant_dir = path.parent
        tenant_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        if not path.exists():
            descriptor, temporary = tempfile.mkstemp(prefix="artifact.", dir=tenant_dir)
            try:
                os.fchmod(descriptor, 0o640)
                with os.fdopen(descriptor, "wb", closefd=True) as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            except Exception:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                raise
        return self.store.register_policy_artifact(
            tenant_id,
            artifact_id,
            family,
            model.model_version,
            content_hash,
            policy_artifact_uri(tenant_id, content_hash),
            metadata=metadata,
        )

    def _load_artifact(self, tenant_id: str, artifact_id: str) -> dict[str, Any]:
        row = self.store.get_policy_artifact(tenant_id, artifact_id)
        path = resolve_policy_artifact(
            self.artifact_dir,
            tenant_id,
            str(row["content_sha256"]),
            str(row["artifact_uri"]),
        )
        encoded = read_verified_policy(path, str(row["content_sha256"]))
        payload = json.loads(encoded)
        if not isinstance(payload, dict):
            raise ValueError("policy artifact must be an object")
        return payload

    def _record_promotion_report(
        self, tenant_id: str, artifact_id: str, report: dict[str, Any]
    ) -> str:
        envelope = self.signer.sign(
            {
                "evidence_kind": "promotion-benchmark",
                "subject_id": artifact_id,
                "artifact_uri": f"policy://{artifact_id}/promotion-report",
                "content_sha256": hashlib.sha256(
                    canonical_json_bytes(report)
                ).hexdigest(),
                "report": report,
            },
            purpose="evidence",
            tenant_id=tenant_id,
            ttl_seconds=None,
        )
        stored = self.store.record_evidence_receipt(tenant_id, envelope)
        return str(stored["receipt_id"])

    def _validate_promotion_benchmark(
        self,
        tenant_id: str,
        artifact_id: str,
        receipt_id: str,
        *,
        enforce_absolute_threshold: bool = True,
    ) -> dict[str, Any]:
        if self.hidden_benchmark is None:
            raise ConflictError("hidden benchmark worker is not configured")
        record = self.store.get_evidence_receipt(tenant_id, receipt_id)
        if record["evidence_kind"] != "hidden-benchmark":
            raise ConflictError("promotion receipt is not a hidden benchmark")
        envelope = record["envelope"]
        issued_at = envelope.get("issued_at")
        if not isinstance(issued_at, int) or isinstance(issued_at, bool):
            raise ConflictError("promotion receipt issue time is invalid")
        age = int(time.time()) - issued_at
        if age < -60 or age > self.settings.benchmark_receipt_max_age_seconds:
            raise ConflictError("hidden benchmark receipt is stale or future-dated")
        payload = envelope.get("payload")
        if not isinstance(payload, dict) or payload.get("policy_artifact_id") != artifact_id:
            raise ConflictError("hidden benchmark is bound to a different challenger")
        artifact = self.store.get_policy_artifact(tenant_id, artifact_id)
        if payload.get("policy_content_sha256") != artifact["content_sha256"]:
            raise ConflictError("hidden benchmark policy content hash does not match")
        aggregate = payload.get("aggregate")
        if not isinstance(aggregate, dict):
            raise ConflictError("hidden benchmark aggregate is missing")
        try:
            authenticated_aggregate = self.verifier.verify(
                aggregate,
                expected_purpose="hidden-benchmark-aggregate",
                expected_tenant_id=self.hidden_benchmark.config.worker_tenant_id,
                replay_guard=None,
            )
        except ReceiptError as error:
            raise ConflictError("hidden benchmark aggregate authentication failed") from error
        aggregate_payload = aggregate.get("payload")
        if not isinstance(aggregate_payload, dict):
            raise ConflictError("hidden benchmark aggregate payload is invalid")
        if authenticated_aggregate != aggregate_payload:
            raise ConflictError("hidden benchmark aggregate payload does not authenticate")
        benchmark = aggregate_payload.get("benchmark")
        candidate = aggregate_payload.get("candidate")
        result = aggregate_payload.get("result")
        if not isinstance(benchmark, dict) or not isinstance(candidate, dict) or not isinstance(result, dict):
            raise ConflictError("hidden benchmark aggregate fields are invalid")
        if benchmark.get("suite_sha256") != opaque_suite_digest(
            self.hidden_benchmark.benchmark_path
        ):
            raise ConflictError("hidden benchmark receipt targets an obsolete suite")
        artifact_path = resolve_policy_artifact(
            self.artifact_dir,
            tenant_id,
            str(artifact["content_sha256"]),
            str(artifact["artifact_uri"]),
        ).resolve(strict=True)
        candidate_script = (
            Path(__file__).resolve().parent / "workers" / "policy_candidate.py"
        )
        expected_fingerprint = candidate_fingerprint(
            [
                str(self.hidden_benchmark.python_executable),
                str(candidate_script),
                str(artifact_path),
            ],
            cwd=Path(__file__).resolve().parent.parent,
        )
        if candidate.get("fingerprint_sha256") != expected_fingerprint:
            raise ConflictError("hidden benchmark candidate fingerprint does not match")
        total = result.get("total")
        score = result.get("normalized_score_ppm")
        if not isinstance(total, int) or isinstance(total, bool) or total <= 0:
            raise ConflictError("hidden benchmark contains no evaluated cases")
        if not isinstance(score, int) or isinstance(score, bool):
            raise ConflictError("hidden benchmark score is invalid")
        if (
            enforce_absolute_threshold
            and score < self.settings.minimum_hidden_benchmark_score_ppm
        ):
            raise ConflictError(
                "hidden benchmark score below promotion threshold: "
                f"{score} < {self.settings.minimum_hidden_benchmark_score_ppm}"
            )
        return {
            "receipt_id": receipt_id,
            "suite_digest": benchmark["suite_sha256"],
            "candidate_fingerprint": expected_fingerprint,
            "total": total,
            "normalized_score_ppm": score,
        }

    def _idempotent(
        self,
        principal: Principal,
        scope: str,
        key: str,
        request: dict[str, Any],
        operation: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        record = self.store.claim_idempotency(
            principal.tenant_id, scope, key, request
        )
        if not record.is_new:
            if record.status == "COMPLETED" and isinstance(record.result, dict):
                return dict(record.result)
            raise ConflictError(f"idempotent operation is {record.status}")
        try:
            result = operation()
            self.store.complete_idempotency(
                principal.tenant_id, scope, key, result
            )
            return result
        except Exception as error:
            current = self.store.claim_idempotency(
                principal.tenant_id, scope, key, request
            )
            if current.status == "COMPLETED" and isinstance(current.result, dict):
                return dict(current.result)
            self.store.fail_idempotency(
                principal.tenant_id,
                scope,
                key,
                {"error_type": type(error).__name__},
            )
            raise

    def _complete_atomic(
        self,
        principal: Principal,
        scope: str,
        key: str,
        result: dict[str, Any],
    ) -> None:
        """Finalize the request inside the caller's state/audit transaction."""

        self.store.complete_idempotency(
            principal.tenant_id, scope, key, result
        )


def _bounded_int(
    payload: dict[str, Any], name: str, default: int, minimum: int, maximum: int
) -> int:
    value = payload.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be in [{minimum}, {maximum}]")
    return value


def _require_allowed_fields(payload: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(str(key) for key in set(payload).difference(allowed))
    if unknown:
        raise ValueError("unknown request fields: " + ", ".join(unknown))


def _bounded_text(
    payload: dict[str, Any],
    name: str,
    default: str,
    maximum_bytes: int,
) -> str:
    value = payload.get(name, default)
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum_bytes
    ):
        raise ValueError(f"{name} must be a nonempty string of at most {maximum_bytes} bytes")
    return value
