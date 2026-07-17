"""Offline challenger training and deterministic promotion gates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from statistics import mean
from typing import Callable, Iterable

from .engine import (
    PUCTSearch,
    PolicyValueModel,
    default_benchmark,
    default_scenario,
    learn_from_result,
    shadow_benchmark_agents,
)

from .serde import model_to_payload


@dataclass(frozen=True)
class EvaluationSummary:
    mean_reward: float
    minimum_reward: float
    hard_gate_failures: int
    abstentions: int
    mean_benchmark_evaluations: float
    cases: int


@dataclass(frozen=True)
class PromotionReport:
    accepted: bool
    reasons: tuple[str, ...]
    champion: EvaluationSummary
    challenger: EvaluationSummary
    reward_delta: float
    artifact_id: str

    def to_payload(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "reasons": list(self.reasons),
            "champion": self.champion.__dict__,
            "challenger": self.challenger.__dict__,
            "reward_delta": self.reward_delta,
            "artifact_id": self.artifact_id,
        }


@dataclass(frozen=True)
class PromotionPolicy:
    minimum_mean_reward_delta: float = 0.02
    maximum_evaluation_ratio: float = 1.25
    require_no_new_hard_failures: bool = True
    require_no_more_abstentions: bool = True


class OfflineLearner:
    def __init__(self, *, family: str = "agent-decision-routing") -> None:
        self.family = family

    def train_challenger(
        self,
        champion: PolicyValueModel,
        *,
        episodes: int = 12,
        simulations: int = 128,
        seed: int = 1_000,
        heartbeat: Callable[[int], None] | None = None,
    ) -> PolicyValueModel:
        if not 1 <= episodes <= 10_000 or not 8 <= simulations <= 100_000:
            raise ValueError("training budget outside safe configured bounds")
        challenger = champion.frozen_copy()
        scenario = default_scenario()
        benchmark = default_benchmark(scenario)
        for episode in range(episodes):
            if heartbeat is not None:
                heartbeat(episode)
            result = PUCTSearch(
                scenario,
                benchmark,
                challenger,
                seed=seed + episode,
                root_noise_fraction=0.18,
            ).run(simulations=simulations)
            learn_from_result(scenario, benchmark, challenger, result)
            shadow_benchmark_agents(scenario, benchmark, challenger)
        return challenger

    def evaluate(
        self,
        model: PolicyValueModel,
        *,
        seeds: Iterable[int] = (7, 17, 29, 43),
        simulation_budgets: Iterable[int] = (16, 32, 64),
    ) -> EvaluationSummary:
        scenario = default_scenario()
        benchmark = default_benchmark(scenario)
        rewards: list[float] = []
        hard_failures = 0
        abstentions = 0
        evaluations: list[int] = []
        for budget in simulation_budgets:
            if not 1 <= budget <= 100_000:
                raise ValueError("evaluation simulation budget outside safe bounds")
            for seed in seeds:
                result = PUCTSearch(
                    scenario, benchmark, model, seed=int(seed)
                ).run(simulations=int(budget))
                rewards.append(result.score.reward)
                evaluations.append(result.benchmark_evaluations)
                abstentions += int(result.abstained)
                hard_failures += int(not result.score.feasible)
        if not rewards:
            raise ValueError("evaluation set must not be empty")
        return EvaluationSummary(
            mean_reward=mean(rewards),
            minimum_reward=min(rewards),
            hard_gate_failures=hard_failures,
            abstentions=abstentions,
            mean_benchmark_evaluations=mean(evaluations),
            cases=len(rewards),
        )

    def promotion_report(
        self,
        champion: PolicyValueModel,
        challenger: PolicyValueModel,
        *,
        policy: PromotionPolicy = PromotionPolicy(),
    ) -> PromotionReport:
        champion_summary = self.evaluate(champion)
        challenger_summary = self.evaluate(challenger)
        delta = challenger_summary.mean_reward - champion_summary.mean_reward
        reasons: list[str] = []
        if delta < policy.minimum_mean_reward_delta:
            reasons.append(
                f"mean reward delta {delta:.6f} below {policy.minimum_mean_reward_delta:.6f}"
            )
        if (
            policy.require_no_new_hard_failures
            and challenger_summary.hard_gate_failures
            > champion_summary.hard_gate_failures
        ):
            reasons.append("challenger introduces hard-gate failures")
        if (
            policy.require_no_more_abstentions
            and challenger_summary.abstentions > champion_summary.abstentions
        ):
            reasons.append("challenger increases abstention count")
        allowed_evaluations = max(
            1.0,
            champion_summary.mean_benchmark_evaluations
            * policy.maximum_evaluation_ratio,
        )
        if challenger_summary.mean_benchmark_evaluations > allowed_evaluations:
            reasons.append("challenger exceeds benchmark-evaluation cost ratio")
        artifact_payload = model_to_payload(challenger, family=self.family)
        artifact_id = "sha256:" + hashlib.sha256(
            json.dumps(
                artifact_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        return PromotionReport(
            accepted=not reasons,
            reasons=tuple(reasons),
            champion=champion_summary,
            challenger=challenger_summary,
            reward_delta=delta,
            artifact_id=artifact_id,
        )
