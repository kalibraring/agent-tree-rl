"""Stable JSON representations for policy artifacts and experience receipts."""

from __future__ import annotations

from typing import Any, Mapping

from .engine import AgentRecord, PolicyValueModel, SearchResult


SCHEMA_VERSION = "agent-tree-rl/v1"


def model_to_payload(model: PolicyValueModel, *, family: str) -> dict[str, Any]:
    snapshot = model.snapshot()
    return {
        "schema": SCHEMA_VERSION,
        "kind": "policy-artifact",
        "family": family,
        "model_version": model.model_version,
        "generation": model.generation,
        "policy_weights": dict(sorted(model.policy_weights.items())),
        "value_weights": dict(sorted(model.value_weights.items())),
        "value_bias": model.value_bias,
        "value_updates": model.value_updates,
        "agent_records": {
            actor: {
                "alpha": record.alpha,
                "beta": record.beta,
                "benched": record.benched,
            }
            for actor, record in sorted(model.agent_records.items())
        },
        "limits": {
            "policy_limit": model.policy_limit,
            "value_limit": model.value_limit,
            "bench_min_samples": model.bench_min_samples,
            "bench_upper_threshold": model.bench_upper_threshold,
        },
        "summary": snapshot,
    }


def model_from_payload(payload: Mapping[str, Any]) -> PolicyValueModel:
    if payload.get("schema") != SCHEMA_VERSION or payload.get("kind") != "policy-artifact":
        raise ValueError("unsupported policy artifact schema")
    limits = _mapping(payload.get("limits"), "limits")
    raw_records = _mapping(payload.get("agent_records"), "agent_records")
    records: dict[str, AgentRecord] = {}
    for actor, raw in raw_records.items():
        value = _mapping(raw, f"agent_records.{actor}")
        records[str(actor)] = AgentRecord(
            alpha=float(value["alpha"]),
            beta=float(value["beta"]),
            benched=bool(value["benched"]),
        )
    model = PolicyValueModel(
        policy_weights={
            str(key): float(value)
            for key, value in _mapping(payload.get("policy_weights"), "policy_weights").items()
        },
        value_weights={
            str(key): float(value)
            for key, value in _mapping(payload.get("value_weights"), "value_weights").items()
        },
        value_bias=float(payload["value_bias"]),
        value_updates=int(payload["value_updates"]),
        generation=int(payload["generation"]),
        agent_records=records,
        policy_limit=float(limits["policy_limit"]),
        value_limit=float(limits["value_limit"]),
        bench_min_samples=int(limits["bench_min_samples"]),
        bench_upper_threshold=float(limits["bench_upper_threshold"]),
    )
    if model.model_version != payload.get("model_version"):
        raise ValueError("policy artifact model version does not reproduce")
    return model


def search_result_to_experience(
    result: SearchResult, *, tenant_id: str, family: str, run_id: str
) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "kind": "experience",
        "tenant_id": tenant_id,
        "family": family,
        "run_id": run_id,
        "scenario_version": result.scenario_version,
        "scenario_manifest_hash": result.scenario_manifest_hash,
        "benchmark_profile_hash": result.benchmark_profile_hash,
        "model_version": result.model_version,
        "simulations": result.simulations,
        "benchmark_evaluations": result.benchmark_evaluations,
        "abstained": result.abstained,
        "trajectory": [
            {"id": move.id, "content_hash": move.content_hash, "actor": move.actor}
            for move in result.trajectory
        ],
        "final_state_hash": result.final_position.state_hash,
        "score": {
            "metrics": dict(sorted(result.score.metrics.items())),
            "composite": result.score.composite,
            "cost_penalty": result.score.cost_penalty,
            "reward": result.score.reward,
            "feasible": result.score.feasible,
            "gate_failures": list(result.score.gate_failures),
            "outcome_status": (
                result.score.outcome_status.value if result.score.outcome_status else None
            ),
        },
        "policy_targets": [
            {
                "receipt_hash": target.receipt_hash,
                "state_hash": target.position.state_hash,
                "candidate_hashes": [list(item) for item in target.candidate_hashes],
                "target_probabilities": dict(sorted(target.target_probabilities.items())),
            }
            for target in result.policy_targets
        ],
        "learning_receipt_hash": result.learning_receipt_hash,
    }


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value
