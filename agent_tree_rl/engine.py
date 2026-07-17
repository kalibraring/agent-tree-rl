"""Pure logic for the Agent Tree RL synthetic reference fixture.

Question under test:
Can a chess-like, typed discussion tree combine multi-agent proposals, weighted
benchmarks, PUCT search, and bounded learning without allowing the learner to
rewrite the definition of success?

This module performs no I/O. The terminal shell in
examples/synthetic_terminal.py is an explanatory example. The built-in fixture
does not invoke real agents or prove improvement outside its synthetic cases.
The fixture is synthetic: candidate predictions and independent benchmark
receipts are intentionally separate, but neither comes from real tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
import math
import random
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence


_ALLOWED_EVIDENCE_PREFIXES = frozenset(
    {"trace://", "env://", "device://", "cloud://"}
)
_SYSTEM_ABSTAIN_TEXT = "No searched terminal branch passed every hard gate."


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _frozen_float_map(values: Mapping[str, float]) -> Mapping[str, float]:
    return MappingProxyType({str(key): float(value) for key, value in values.items()})


class MoveKind(str, Enum):
    PROPOSE = "PROPOSE"
    QUESTION = "QUESTION"
    ANSWER = "ANSWER"
    COMMIT = "COMMIT"
    ABSTAIN = "ABSTAIN"


class TerminalStatus(str, Enum):
    COMMITTED = "COMMITTED"
    ABSTAINED = "ABSTAINED"


@dataclass(frozen=True)
class Move:
    """One immutable chess-like edge, bound to canonical structured content."""

    id: str
    action_key: str
    kind: MoveKind
    actor: str
    text: str
    base_prior: float
    predicted_metrics: Mapping[str, float]
    cost: float
    tags: tuple[str, ...]
    opens_question: str | None = None
    requires_question: str | None = None
    resolves_question: str | None = None
    evidence_refs: tuple[str, ...] = ()
    violations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.action_key or not self.actor:
            raise ValueError("move id, action_key, and actor must not be empty")
        if not math.isfinite(self.base_prior) or self.base_prior <= 0.0:
            raise ValueError(f"move {self.id}: base_prior must be finite and positive")
        if not math.isfinite(self.cost) or self.cost < 0.0:
            raise ValueError(f"move {self.id}: cost must be finite and nonnegative")
        frozen_metrics = _frozen_float_map(self.predicted_metrics)
        for name, value in frozen_metrics.items():
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"move {self.id}: predicted metric {name} must be in [0, 1]"
                )
        object.__setattr__(self, "predicted_metrics", frozen_metrics)
        object.__setattr__(self, "tags", tuple(self.tags))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "violations", tuple(self.violations))

    @property
    def semantic_signature(self) -> str:
        """Structured action identity; prose and predictions do not define novelty."""

        return _digest(
            {
                "action_key": self.action_key,
                "kind": self.kind.value,
                "actor": self.actor,
                "tags": sorted(self.tags),
                "opens": self.opens_question,
                "requires": self.requires_question,
                "resolves": self.resolves_question,
                "evidence_refs": sorted(self.evidence_refs),
                "violations": sorted(self.violations),
            }
        )

    @property
    def content_hash(self) -> str:
        """Full audit identity, including every transition- or reward-relevant field."""

        return _digest(
            {
                "id": self.id,
                "action_key": self.action_key,
                "kind": self.kind.value,
                "actor": self.actor,
                "text": self.text,
                "base_prior": self.base_prior,
                "predicted_metrics": dict(sorted(self.predicted_metrics.items())),
                "cost": self.cost,
                "tags": list(self.tags),
                "opens": self.opens_question,
                "requires": self.requires_question,
                "resolves": self.resolves_question,
                "evidence_refs": list(self.evidence_refs),
                "violations": list(self.violations),
            }
        )


@dataclass(frozen=True)
class Position:
    scenario: str
    scenario_version: str
    phase: int = 0
    trajectory: tuple[Move, ...] = ()
    open_questions: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    spent_cost: float = 0.0
    violations: tuple[str, ...] = ()
    terminal_status: TerminalStatus | None = None

    @property
    def terminal(self) -> bool:
        return self.terminal_status is not None

    @property
    def state_hash(self) -> str:
        """Full state digest. Callers may abbreviate it for display only."""

        return _digest(
            {
                "scenario": self.scenario,
                "scenario_version": self.scenario_version,
                "phase": self.phase,
                "move_hashes": [move.content_hash for move in self.trajectory],
                "open_questions": sorted(self.open_questions),
                "evidence_refs": sorted(self.evidence_refs),
                "spent_cost": self.spent_cost,
                "violations": sorted(self.violations),
                "terminal_status": (
                    self.terminal_status.value if self.terminal_status else None
                ),
            }
        )


@dataclass(frozen=True)
class BenchmarkMetric:
    name: str
    weight: float
    hard_minimum: float | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("benchmark metric name must not be empty")
        if not math.isfinite(self.weight) or self.weight < 0.0:
            raise ValueError(f"metric {self.name}: weight must be finite and nonnegative")
        if self.hard_minimum is not None and (
            not math.isfinite(self.hard_minimum)
            or not 0.0 <= self.hard_minimum <= 1.0
        ):
            raise ValueError(f"metric {self.name}: hard minimum must be in [0, 1]")


@dataclass(frozen=True)
class ScoreCard:
    metrics: Mapping[str, float]
    composite: float
    cost_penalty: float
    reward: float
    feasible: bool
    gate_failures: tuple[str, ...]
    outcome_status: TerminalStatus | None


@dataclass(frozen=True)
class BenchmarkSuite:
    """Governed fixture evaluator, independent of candidate-predicted metrics."""

    version: str
    scenario_manifest_hash: str
    metrics: tuple[BenchmarkMetric, ...]
    # Keyed by canonical move content hash, never by caller-controlled move ID.
    receipt_metrics: Mapping[str, Mapping[str, float]]
    phase_importance: tuple[float, ...]
    cost_weight: float = 0.08
    critical_safety_minimum: float = 0.45
    violation_reward: float = -1.0
    abstain_reward: float = -0.25
    trusted_evidence_prefixes: tuple[str, ...] = (
        "trace://",
        "env://",
        "device://",
        "cloud://",
    )

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("benchmark version must not be empty")
        if (
            len(self.scenario_manifest_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.scenario_manifest_hash)
        ):
            raise ValueError("benchmark must bind a full scenario manifest hash")
        names = [metric.name for metric in self.metrics]
        if not names or len(names) != len(set(names)):
            raise ValueError("benchmark metric names must be nonempty and unique")
        total = sum(metric.weight for metric in self.metrics)
        if not math.isclose(total, 1.0, abs_tol=1e-9):
            raise ValueError(f"benchmark weights must sum to 1.0, got {total}")
        if not self.phase_importance or any(
            not math.isfinite(value) or value <= 0.0
            for value in self.phase_importance
        ):
            raise ValueError("phase importance values must be finite and positive")
        if not math.isfinite(self.cost_weight) or not 0.0 <= self.cost_weight <= 1.0:
            raise ValueError("cost_weight must be finite and in [0, 1]")
        if (
            not math.isfinite(self.critical_safety_minimum)
            or not 0.0 <= self.critical_safety_minimum <= 1.0
        ):
            raise ValueError("critical safety minimum must be in [0, 1]")
        if not math.isfinite(self.violation_reward) or not -1.0 <= self.violation_reward <= 0.0:
            raise ValueError("violation_reward must be finite and in [-1, 0]")
        if not math.isfinite(self.abstain_reward) or not -1.0 <= self.abstain_reward <= 0.0:
            raise ValueError("abstain_reward must be finite and in [-1, 0]")
        prefixes = tuple(self.trusted_evidence_prefixes)
        if (
            not prefixes
            or len(prefixes) != len(set(prefixes))
            or any(not prefix for prefix in prefixes)
            or not set(prefixes).issubset(_ALLOWED_EVIDENCE_PREFIXES)
        ):
            raise ValueError(
                "trusted evidence prefixes must be unique, nonempty, and fixture-approved"
            )

        frozen_receipts: dict[str, Mapping[str, float]] = {}
        for move_hash, values in self.receipt_metrics.items():
            if (
                len(move_hash) != 64
                or any(character not in "0123456789abcdef" for character in move_hash)
            ):
                raise ValueError("benchmark receipt key must be a canonical move hash")
            frozen = _frozen_float_map(values)
            missing = [name for name in names if name not in frozen]
            if missing:
                raise ValueError(f"receipt {move_hash}: missing benchmark metrics {missing}")
            for name, value in frozen.items():
                if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                    raise ValueError(f"receipt {move_hash}: metric {name} must be in [0, 1]")
            frozen_receipts[str(move_hash)] = frozen
        object.__setattr__(
            self, "receipt_metrics", MappingProxyType(frozen_receipts)
        )
        object.__setattr__(self, "phase_importance", tuple(self.phase_importance))
        object.__setattr__(
            self, "trusted_evidence_prefixes", tuple(self.trusted_evidence_prefixes)
        )

    @property
    def profile_hash(self) -> str:
        return _digest(
            {
                "version": self.version,
                "scenario_manifest_hash": self.scenario_manifest_hash,
                "metrics": [
                    {
                        "name": metric.name,
                        "weight": metric.weight,
                        "hard_minimum": metric.hard_minimum,
                    }
                    for metric in self.metrics
                ],
                "receipts": {
                    move_id: dict(sorted(values.items()))
                    for move_id, values in sorted(self.receipt_metrics.items())
                },
                "phase_importance": list(self.phase_importance),
                "cost_weight": self.cost_weight,
                "critical_safety_minimum": self.critical_safety_minimum,
                "violation_reward": self.violation_reward,
                "abstain_reward": self.abstain_reward,
                "trusted_evidence_prefixes": list(self.trusted_evidence_prefixes),
            }
        )

    def predicted_move_quality(self, move: Move) -> float:
        """Cheap proposer estimate for rollout policy, never terminal reward."""

        missing = [
            metric.name
            for metric in self.metrics
            if metric.name not in move.predicted_metrics
        ]
        if missing:
            raise ValueError(f"move {move.id}: missing predicted metrics {missing}")
        quality = sum(
            metric.weight * move.predicted_metrics[metric.name]
            for metric in self.metrics
        )
        return max(0.0, min(1.0, quality - self.cost_weight * move.cost))

    def receipt_move_quality(self, move: Move) -> float:
        """Independent scripted receipt used only for the fixture shadow league."""

        if move.content_hash not in self.receipt_metrics:
            raise ValueError(f"missing independent receipt for move {move.id}")
        values = self.receipt_metrics[move.content_hash]
        return sum(metric.weight * values[metric.name] for metric in self.metrics)

    def evaluate(self, position: Position) -> ScoreCard:
        empty = MappingProxyType({metric.name: 0.0 for metric in self.metrics})
        if position.terminal_status is TerminalStatus.ABSTAINED:
            system_fallback = (
                len(position.trajectory) == 1
                and position.trajectory[0].id == "SYSTEM_ABSTAIN"
            )
            if not system_fallback:
                totals = {metric.name: 0.0 for metric in self.metrics}
                denominator = 0.0
                warnings: list[str] = list(position.violations)
                for phase, move in enumerate(position.trajectory):
                    if move.kind is MoveKind.ABSTAIN:
                        continue
                    receipt = self.receipt_metrics.get(move.content_hash)
                    if receipt is None:
                        warnings.append(
                            f"missing independent benchmark receipt for {move.id}"
                        )
                        continue
                    importance = (
                        self.phase_importance[phase]
                        if phase < len(self.phase_importance)
                        else 0.0
                    )
                    denominator += importance
                    for metric in self.metrics:
                        totals[metric.name] += receipt[metric.name] * importance
                    safety = receipt.get("safety")
                    if (
                        safety is not None
                        and safety < self.critical_safety_minimum
                    ):
                        warnings.append(
                            f"{move.id} safety={safety:.3f} below critical threshold"
                        )
                values = {
                    name: (total / denominator if denominator > 0.0 else 0.0)
                    for name, total in totals.items()
                }
                composite = sum(
                    metric.weight * values[metric.name]
                    for metric in self.metrics
                )
                cost_penalty = self.cost_weight * position.spent_cost
                return ScoreCard(
                    metrics=MappingProxyType(values),
                    composite=composite,
                    cost_penalty=cost_penalty,
                    reward=max(-1.0, self.abstain_reward - cost_penalty),
                    # Abstention causes no commit effect, so warnings remain
                    # visible without making the safe terminal ineligible.
                    feasible=True,
                    gate_failures=tuple(dict.fromkeys(warnings)),
                    outcome_status=position.terminal_status,
                )
            return ScoreCard(
                metrics=empty,
                composite=0.0,
                cost_penalty=0.0,
                reward=self.abstain_reward,
                feasible=True,
                gate_failures=(),
                outcome_status=position.terminal_status,
            )

        failures: list[str] = list(position.violations)
        if position.terminal_status is not TerminalStatus.COMMITTED:
            failures.append("position has no explicit COMMIT or ABSTAIN terminal")
        if position.open_questions:
            failures.append("unresolved proof obligation")
        if len(position.trajectory) != len(self.phase_importance):
            failures.append(
                f"terminal path has {len(position.trajectory)} plies; expected {len(self.phase_importance)}"
            )

        trusted_evidence = tuple(
            ref
            for ref in position.evidence_refs
            if ref.startswith(self.trusted_evidence_prefixes)
        )
        if not trusted_evidence:
            failures.append("no trusted evidence receipt")

        totals = {metric.name: 0.0 for metric in self.metrics}
        denominator = 0.0
        for phase, move in enumerate(position.trajectory):
            receipt = self.receipt_metrics.get(move.content_hash)
            if receipt is None:
                failures.append(f"missing independent benchmark receipt for {move.id}")
                continue
            importance = (
                self.phase_importance[phase]
                if phase < len(self.phase_importance)
                else 0.0
            )
            denominator += importance
            for metric in self.metrics:
                totals[metric.name] += receipt[metric.name] * importance
            safety = receipt.get("safety")
            if safety is not None and safety < self.critical_safety_minimum:
                failures.append(
                    f"{move.id} safety={safety:.3f} < critical={self.critical_safety_minimum:.3f}"
                )

        values = {
            name: (total / denominator if denominator > 0.0 else 0.0)
            for name, total in totals.items()
        }
        for metric in self.metrics:
            value = values[metric.name]
            if metric.hard_minimum is not None and value < metric.hard_minimum:
                failures.append(
                    f"{metric.name}={value:.3f} < gate={metric.hard_minimum:.3f}"
                )

        unique_failures = tuple(dict.fromkeys(failures))
        composite = sum(
            metric.weight * values[metric.name] for metric in self.metrics
        )
        cost_penalty = self.cost_weight * position.spent_cost
        unconstrained = max(
            -1.0, min(1.0, 2.0 * composite - 1.0 - cost_penalty)
        )
        feasible = not unique_failures
        reward = unconstrained if feasible else self.violation_reward
        return ScoreCard(
            metrics=MappingProxyType(values),
            composite=composite,
            cost_penalty=cost_penalty,
            reward=reward,
            feasible=feasible,
            gate_failures=unique_failures,
            outcome_status=position.terminal_status,
        )


@dataclass(frozen=True)
class Scenario:
    name: str
    version: str
    description: str
    phases: tuple[tuple[Move, ...], ...]

    def __post_init__(self) -> None:
        if not self.name or not self.version:
            raise ValueError("scenario name and version must not be empty")
        expected = (
            frozenset({MoveKind.PROPOSE}),
            frozenset({MoveKind.QUESTION}),
            frozenset({MoveKind.ANSWER}),
            frozenset({MoveKind.COMMIT, MoveKind.ABSTAIN}),
        )
        if len(self.phases) != len(expected):
            raise ValueError("synthetic scenario must contain exactly four typed phases")
        ids: set[str] = set()
        for phase_index, phase in enumerate(self.phases):
            signatures: set[str] = set()
            if not phase:
                raise ValueError(f"phase {phase_index} must contain candidates")
            for move in phase:
                if move.kind not in expected[phase_index]:
                    raise ValueError(
                        f"move {move.id}: {move.kind.value} illegal in phase {phase_index}"
                    )
                if move.id in ids:
                    raise ValueError(f"duplicate move id {move.id}")
                ids.add(move.id)
                if move.semantic_signature in signatures:
                    raise ValueError(
                        f"phase {phase_index}: duplicate semantic move {move.id}"
                    )
                signatures.add(move.semantic_signature)
                if move.kind is MoveKind.QUESTION:
                    if not move.opens_question:
                        raise ValueError(f"question {move.id} must open an obligation")
                    if move.requires_question or move.resolves_question:
                        raise ValueError(f"question {move.id} has invalid Q&A linkage")
                elif move.kind is MoveKind.ANSWER:
                    if (
                        not move.requires_question
                        or not move.resolves_question
                        or move.requires_question != move.resolves_question
                    ):
                        raise ValueError(
                            f"answer {move.id} must require and resolve the same open question"
                        )
                elif move.opens_question or move.requires_question or move.resolves_question:
                    raise ValueError(f"move {move.id}: Q&A linkage invalid for {move.kind}")

    def initial_position(self) -> Position:
        return Position(scenario=self.name, scenario_version=self.version)

    @property
    def manifest_hash(self) -> str:
        return _digest(
            {
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "phases": [
                    [move.content_hash for move in phase] for phase in self.phases
                ],
            }
        )

    def _assert_position(self, position: Position) -> None:
        if position.scenario != self.name or position.scenario_version != self.version:
            raise ValueError("position belongs to a different scenario version")

    def legal_moves(
        self, position: Position, benched_agents: frozenset[str] = frozenset()
    ) -> tuple[Move, ...]:
        self._assert_position(position)
        if position.terminal or position.phase >= len(self.phases):
            return ()
        legal: list[Move] = []
        for move in self.phases[position.phase]:
            if move.actor in benched_agents:
                continue
            if (
                move.kind is MoveKind.ANSWER
                and move.requires_question not in position.open_questions
            ):
                continue
            legal.append(move)
        return tuple(legal)

    def apply(
        self,
        position: Position,
        move: Move,
        benched_agents: frozenset[str] = frozenset(),
    ) -> Position:
        """Apply only the canonical candidate; forged same-ID payloads fail closed."""

        canonical_by_id = {
            candidate.id: candidate
            for candidate in self.legal_moves(position, benched_agents)
        }
        canonical = canonical_by_id.get(move.id)
        if canonical is None:
            raise ValueError(f"illegal move {move.id!r} at phase {position.phase}")
        if move.content_hash != canonical.content_hash:
            raise ValueError(f"move {move.id!r} does not match canonical content")

        open_questions = list(position.open_questions)
        if canonical.opens_question:
            if canonical.opens_question in open_questions:
                raise ValueError(f"question {canonical.opens_question!r} is already open")
            open_questions.append(canonical.opens_question)
        if canonical.resolves_question:
            if canonical.resolves_question not in open_questions:
                raise ValueError(
                    f"answer {canonical.id} targets a question that is not open"
                )
            open_questions.remove(canonical.resolves_question)

        terminal_status: TerminalStatus | None = None
        if canonical.kind is MoveKind.COMMIT:
            terminal_status = TerminalStatus.COMMITTED
        elif canonical.kind is MoveKind.ABSTAIN:
            terminal_status = TerminalStatus.ABSTAINED

        return replace(
            position,
            phase=position.phase + 1,
            trajectory=position.trajectory + (canonical,),
            open_questions=tuple(open_questions),
            evidence_refs=tuple(
                dict.fromkeys(position.evidence_refs + canonical.evidence_refs)
            ),
            spent_cost=position.spent_cost + canonical.cost,
            violations=tuple(
                dict.fromkeys(position.violations + canonical.violations)
            ),
            terminal_status=terminal_status,
        )

    def safe_abstain(self, reason: str = _SYSTEM_ABSTAIN_TEXT) -> Position:
        predicted_names = next(iter(self.phases[0])).predicted_metrics.keys()
        move = Move(
            id="SYSTEM_ABSTAIN",
            action_key="system.safe-abstain",
            kind=MoveKind.ABSTAIN,
            actor="Orchestrator",
            text=reason,
            base_prior=1.0,
            predicted_metrics={name: 0.0 for name in predicted_names},
            cost=0.0,
            tags=("safe-abstain",),
        )
        return replace(
            self.initial_position(),
            trajectory=(move,),
            terminal_status=TerminalStatus.ABSTAINED,
        )


@dataclass
class AgentRecord:
    alpha: float = 1.0
    beta: float = 1.0
    benched: bool = False

    @property
    def samples(self) -> float:
        return self.alpha + self.beta - 2.0

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def standard_deviation(self) -> float:
        total = self.alpha + self.beta
        variance = self.alpha * self.beta / (total * total * (total + 1.0))
        return math.sqrt(variance)

    @property
    def upper_confidence(self) -> float:
        return min(1.0, self.mean + 1.64 * self.standard_deviation)

    def observe(self, quality: float) -> None:
        if not math.isfinite(quality):
            raise ValueError("agent quality observation must be finite")
        bounded = max(0.0, min(1.0, quality))
        self.alpha += bounded
        self.beta += 1.0 - bounded


@dataclass
class PolicyValueModel:
    """Bounded overlay. Bench state is durable until explicit recertification."""

    policy_weights: dict[str, float] = field(default_factory=dict)
    value_weights: dict[str, float] = field(default_factory=dict)
    value_bias: float = 0.0
    value_updates: int = 0
    generation: int = 0
    agent_records: dict[str, AgentRecord] = field(default_factory=dict)
    policy_limit: float = 2.5
    value_limit: float = 2.5
    bench_min_samples: int = 8
    bench_upper_threshold: float = 0.58

    def __post_init__(self) -> None:
        if (
            not math.isfinite(self.policy_limit)
            or self.policy_limit <= 0.0
            or not math.isfinite(self.value_limit)
            or self.value_limit <= 0.0
        ):
            raise ValueError("model coordinate limits must be finite and positive")
        if not isinstance(self.bench_min_samples, int) or self.bench_min_samples <= 0:
            raise ValueError("bench_min_samples must be a positive integer")
        if (
            not math.isfinite(self.bench_upper_threshold)
            or not 0.0 <= self.bench_upper_threshold <= 1.0
        ):
            raise ValueError("bench threshold must be finite and in [0, 1]")
        if not isinstance(self.generation, int) or self.generation < 0:
            raise ValueError("model generation must be a nonnegative integer")
        if not isinstance(self.value_updates, int) or self.value_updates < 0:
            raise ValueError("value update count must be a nonnegative integer")
        if not math.isfinite(self.value_bias) or abs(self.value_bias) > self.value_limit:
            raise ValueError("value bias must be finite and within its configured limit")
        for name, value in self.policy_weights.items():
            if not math.isfinite(value) or abs(value) > self.policy_limit:
                raise ValueError(f"policy weight {name} is invalid")
        for name, value in self.value_weights.items():
            if not math.isfinite(value) or abs(value) > self.value_limit:
                raise ValueError(f"value weight {name} is invalid")
        for actor, record in self.agent_records.items():
            if (
                not math.isfinite(record.alpha)
                or not math.isfinite(record.beta)
                or record.alpha <= 0.0
                or record.beta <= 0.0
            ):
                raise ValueError(f"agent record {actor} has invalid posterior counts")

    @property
    def model_version(self) -> str:
        state_hash = _digest(
            {
                "generation": self.generation,
                "policy": dict(sorted(self.policy_weights.items())),
                "value": dict(sorted(self.value_weights.items())),
                "value_bias": self.value_bias,
                "value_updates": self.value_updates,
                "agents": {
                    actor: {
                        "alpha": record.alpha,
                        "beta": record.beta,
                        "benched": record.benched,
                    }
                    for actor, record in sorted(self.agent_records.items())
                },
                "limits": {
                    "policy": self.policy_limit,
                    "value": self.value_limit,
                    "bench_n": self.bench_min_samples,
                    "bench_threshold": self.bench_upper_threshold,
                },
            }
        )
        return f"overlay-g{self.generation}-{state_hash[:12]}"

    def frozen_copy(self) -> PolicyValueModel:
        return PolicyValueModel(
            policy_weights=dict(self.policy_weights),
            value_weights=dict(self.value_weights),
            value_bias=self.value_bias,
            value_updates=self.value_updates,
            generation=self.generation,
            agent_records={
                actor: AgentRecord(
                    alpha=record.alpha,
                    beta=record.beta,
                    benched=record.benched,
                )
                for actor, record in self.agent_records.items()
            },
            policy_limit=self.policy_limit,
            value_limit=self.value_limit,
            bench_min_samples=self.bench_min_samples,
            bench_upper_threshold=self.bench_upper_threshold,
        )

    def record_for(self, actor: str) -> AgentRecord:
        if actor not in self.agent_records:
            self.agent_records[actor] = AgentRecord()
        return self.agent_records[actor]

    def is_benched(self, actor: str) -> bool:
        return self.agent_records.get(actor, AgentRecord()).benched

    @property
    def benched_agents(self) -> frozenset[str]:
        return frozenset(
            actor for actor, record in self.agent_records.items() if record.benched
        )

    def _raw_policy_logit(self, move: Move) -> float:
        base = math.log(max(move.base_prior, 1e-9))
        learned = sum(self.policy_weights.get(tag, 0.0) for tag in move.tags)
        reliability = self.agent_records.get(move.actor, AgentRecord()).mean
        reliability_term = 0.20 * math.log(
            max(reliability, 1e-4) / max(1.0 - reliability, 1e-4)
        )
        return base + learned + reliability_term

    def priors(self, moves: Sequence[Move]) -> dict[str, float]:
        if not moves:
            return {}
        logits = {move.id: self._raw_policy_logit(move) for move in moves}
        if any(not math.isfinite(value) for value in logits.values()):
            raise ValueError("policy produced a non-finite logit")
        peak = max(logits.values())
        exps = {move_id: math.exp(logit - peak) for move_id, logit in logits.items()}
        denominator = sum(exps.values())
        if not math.isfinite(denominator) or denominator <= 0.0:
            uniform = 1.0 / len(moves)
            return {move.id: uniform for move in moves}
        return {move_id: value / denominator for move_id, value in exps.items()}

    @staticmethod
    def _value_features(position: Position) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(tag for move in position.trajectory for tag in move.tags)
        )

    def learned_value(self, position: Position) -> float:
        features = self._value_features(position)
        raw = self.value_bias
        if features:
            raw += sum(self.value_weights.get(tag, 0.0) for tag in features) / len(
                features
            )
        return math.tanh(raw)

    def blend_value(self, position: Position, heuristic: float) -> float:
        learned_share = min(0.50, self.value_updates / 120.0)
        return (1.0 - learned_share) * heuristic + learned_share * self.learned_value(
            position
        )

    @staticmethod
    def _clip(value: float, limit: float) -> float:
        return max(-limit, min(limit, value))

    def learn_policy(
        self,
        moves: Sequence[Move],
        target_probabilities: Mapping[str, float],
        learning_rate: float = 0.18,
    ) -> None:
        if not moves:
            return
        move_ids = {move.id for move in moves}
        if not set(target_probabilities).issubset(move_ids):
            raise ValueError("policy target contains an unknown move")
        values = list(target_probabilities.values())
        if any(not math.isfinite(value) or value < 0.0 for value in values):
            raise ValueError("policy target probabilities must be finite and nonnegative")
        total = sum(values)
        if not math.isclose(total, 1.0, abs_tol=1e-8):
            raise ValueError(f"policy target probabilities must sum to 1.0, got {total}")
        if not math.isfinite(learning_rate) or not 0.0 < learning_rate <= 1.0:
            raise ValueError("policy learning rate must be in (0, 1]")

        predicted = self.priors(moves)
        for move in moves:
            error = target_probabilities.get(move.id, 0.0) - predicted[move.id]
            scale = learning_rate * error / max(1, len(move.tags))
            for tag in move.tags:
                self.policy_weights[tag] = self._clip(
                    self.policy_weights.get(tag, 0.0) + scale,
                    self.policy_limit,
                )

    def learn_value(
        self, position: Position, actual_reward: float, learning_rate: float = 0.12
    ) -> None:
        if not math.isfinite(actual_reward) or not -1.0 <= actual_reward <= 1.0:
            raise ValueError("actual reward must be finite and in [-1, 1]")
        if not math.isfinite(learning_rate) or not 0.0 < learning_rate <= 1.0:
            raise ValueError("value learning rate must be in (0, 1]")
        predicted = self.learned_value(position)
        derivative = 1.0 - predicted * predicted
        error = (actual_reward - predicted) * derivative
        features = self._value_features(position)
        self.value_bias = self._clip(
            self.value_bias + learning_rate * error, self.value_limit
        )
        if features:
            delta = learning_rate * error / len(features)
            for tag in features:
                self.value_weights[tag] = self._clip(
                    self.value_weights.get(tag, 0.0) + delta,
                    self.value_limit,
                )
        self.value_updates += 1

    def observe_benchmark(
        self, move: Move, suite: BenchmarkSuite
    ) -> None:
        record = self.record_for(move.actor)
        record.observe(suite.receipt_move_quality(move))
        if (
            not record.benched
            and record.samples >= self.bench_min_samples
            and record.upper_confidence < self.bench_upper_threshold
        ):
            record.benched = True

    def snapshot(self) -> dict[str, object]:
        return {
            "model_version": self.model_version,
            "policy_weights": dict(sorted(self.policy_weights.items())),
            "value_weights": dict(sorted(self.value_weights.items())),
            "value_bias": self.value_bias,
            "value_updates": self.value_updates,
            "agents": {
                actor: {
                    "samples": record.samples,
                    "mean": record.mean,
                    "upper_confidence": record.upper_confidence,
                    "status": "BENCHED" if record.benched else "ACTIVE",
                }
                for actor, record in sorted(self.agent_records.items())
            },
        }


@dataclass
class SearchNode:
    position: Position
    parent: SearchNode | None = None
    move: Move | None = None
    prior: float = 1.0
    visits: int = 0
    value_sum: float = 0.0
    children: dict[str, SearchNode] = field(default_factory=dict)
    unexpanded: list[Move] | None = None
    candidate_priors: dict[str, float] = field(default_factory=dict)

    @property
    def q_value(self) -> float:
        return self.value_sum / self.visits if self.visits else 0.0


@dataclass(frozen=True)
class PolicyTargetReceipt:
    """Deeply immutable search target; learning never reads live tree statistics."""

    position: Position
    candidate_hashes: tuple[tuple[str, str], ...]
    target_probabilities: Mapping[str, float]

    def __post_init__(self) -> None:
        candidate_hashes = tuple(self.candidate_hashes)
        candidate_ids = [move_id for move_id, _ in candidate_hashes]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("policy target contains duplicate candidate IDs")
        for move_id, content_hash in candidate_hashes:
            if not move_id or len(content_hash) != 64:
                raise ValueError("policy target candidate identity is invalid")
        targets = _frozen_float_map(self.target_probabilities)
        if not set(targets).issubset(candidate_ids):
            raise ValueError("policy target references an unknown candidate")
        if any(not math.isfinite(value) or value < 0.0 for value in targets.values()):
            raise ValueError("policy target values must be finite and nonnegative")
        if not math.isclose(sum(targets.values()), 1.0, abs_tol=1e-8):
            raise ValueError("policy target values must sum to 1.0")
        object.__setattr__(self, "candidate_hashes", candidate_hashes)
        object.__setattr__(self, "target_probabilities", targets)

    @property
    def receipt_hash(self) -> str:
        return _digest(
            {
                "state_hash": self.position.state_hash,
                "candidate_hashes": list(self.candidate_hashes),
                "target_probabilities": dict(
                    sorted(self.target_probabilities.items())
                ),
            }
        )


def _scorecard_payload(score: ScoreCard) -> dict[str, object]:
    return {
        "metrics": dict(sorted(score.metrics.items())),
        "composite": score.composite,
        "cost_penalty": score.cost_penalty,
        "reward": score.reward,
        "feasible": score.feasible,
        "gate_failures": list(score.gate_failures),
        "outcome_status": (
            score.outcome_status.value if score.outcome_status else None
        ),
    }


def _experience_digest(
    *,
    scenario_manifest_hash: str,
    benchmark_profile_hash: str,
    model_version: str,
    trajectory: Sequence[Move],
    final_position: Position,
    score: ScoreCard,
    policy_targets: Sequence[PolicyTargetReceipt],
    abstained: bool,
) -> str:
    return _digest(
        {
            "scenario_manifest_hash": scenario_manifest_hash,
            "benchmark_profile_hash": benchmark_profile_hash,
            "model_version": model_version,
            "trajectory": [move.content_hash for move in trajectory],
            "final_state_hash": final_position.state_hash,
            "score": _scorecard_payload(score),
            "policy_targets": [target.receipt_hash for target in policy_targets],
            "abstained": abstained,
        }
    )


@dataclass(frozen=True)
class SearchResult:
    root: SearchNode
    terminal_node: SearchNode | None
    trajectory: tuple[Move, ...]
    final_position: Position
    score: ScoreCard
    simulations: int
    benchmark_evaluations: int
    scenario_version: str
    scenario_manifest_hash: str
    benchmark_profile_hash: str
    model_version: str
    abstained: bool
    policy_targets: tuple[PolicyTargetReceipt, ...]
    learning_receipt_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "trajectory", tuple(self.trajectory))
        object.__setattr__(self, "policy_targets", tuple(self.policy_targets))
        if (
            len(self.learning_receipt_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.learning_receipt_hash
            )
        ):
            raise ValueError("learning receipt must use a full content hash")

    @property
    def root_distribution(self) -> dict[str, float]:
        total = sum(child.visits for child in self.root.children.values())
        if total == 0:
            return {}
        return {
            move_id: child.visits / total
            for move_id, child in self.root.children.items()
        }


@dataclass(frozen=True)
class BaselineResult:
    trajectory: tuple[Move, ...]
    final_position: Position
    score: ScoreCard


class PUCTSearch:
    def __init__(
        self,
        scenario: Scenario,
        benchmark: BenchmarkSuite,
        model: PolicyValueModel,
        c_puct: float = 1.5,
        seed: int = 7,
        root_noise_fraction: float = 0.0,
    ) -> None:
        if not math.isfinite(c_puct) or c_puct < 0.0:
            raise ValueError("c_puct must be finite and nonnegative")
        if not 0.0 <= root_noise_fraction <= 1.0:
            raise ValueError("root noise fraction must be in [0, 1]")
        if benchmark.scenario_manifest_hash != scenario.manifest_hash:
            raise ValueError("benchmark is bound to a different scenario manifest")
        scenario_move_hashes = {
            move.content_hash
            for phase in scenario.phases
            for move in phase
            if move.kind is not MoveKind.ABSTAIN
        }
        missing_receipts = scenario_move_hashes - set(benchmark.receipt_metrics)
        if missing_receipts:
            raise ValueError(
                f"benchmark lacks canonical move receipts: {sorted(missing_receipts)}"
            )
        if len(benchmark.phase_importance) != len(scenario.phases):
            raise ValueError("benchmark phase weights do not match scenario")

        self.scenario = scenario
        self.benchmark = benchmark
        self.model = model.frozen_copy()
        self.c_puct = c_puct
        self.random = random.Random(seed)
        self.root_noise_fraction = root_noise_fraction
        self.benchmark_evaluations = 0
        self._score_cache: dict[str, ScoreCard] = {}

    def _score(self, position: Position) -> ScoreCard:
        cached = self._score_cache.get(position.state_hash)
        if cached is not None:
            return cached
        score = self.benchmark.evaluate(position)
        self._score_cache[position.state_hash] = score
        self.benchmark_evaluations += 1
        return score

    def _initialise(self, node: SearchNode, root: bool = False) -> None:
        legal = list(
            self.scenario.legal_moves(node.position, self.model.benched_agents)
        )
        priors = self.model.priors(legal)
        if root and legal and self.root_noise_fraction > 0.0:
            noise = [self.random.gammavariate(0.3, 1.0) for _ in legal]
            total = sum(noise)
            for move, draw in zip(legal, noise):
                original = priors[move.id]
                priors[move.id] = (
                    (1.0 - self.root_noise_fraction) * original
                    + self.root_noise_fraction * draw / total
                )
        node.candidate_priors = priors
        node.unexpanded = sorted(
            legal, key=lambda move: (-priors[move.id], move.id)
        )

    def _select_child(self, node: SearchNode) -> SearchNode:
        parent_visits = max(1, node.visits)

        def score(child: SearchNode) -> tuple[float, str]:
            exploration = (
                self.c_puct
                * child.prior
                * math.sqrt(parent_visits)
                / (1 + child.visits)
            )
            # Q already contains governed cost. Do not subtract cost twice.
            return child.q_value + exploration, child.move.id if child.move else ""

        return max(node.children.values(), key=score)

    def _greedy_completion(self, position: Position) -> Position:
        current = position
        while not current.terminal:
            legal = self.scenario.legal_moves(
                current, self.model.benched_agents
            )
            if not legal:
                return current
            priors = self.model.priors(legal)
            move = max(
                legal,
                key=lambda candidate: (
                    0.78 * self.benchmark.predicted_move_quality(candidate)
                    + 0.22 * priors[candidate.id],
                    candidate.id,
                ),
            )
            current = self.scenario.apply(
                current, move, self.model.benched_agents
            )
        return current

    def _evaluate_leaf(self, position: Position) -> float:
        completed = self._greedy_completion(position)
        if not completed.terminal:
            return self.benchmark.violation_reward
        heuristic = self._score(completed).reward
        return self.model.blend_value(position, heuristic)

    @staticmethod
    def _terminal_nodes(root: SearchNode) -> list[SearchNode]:
        found: list[SearchNode] = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.position.terminal:
                found.append(node)
            stack.extend(node.children.values())
        return found

    @staticmethod
    def _path_to(node: SearchNode) -> tuple[Move, ...]:
        moves: list[Move] = []
        current: SearchNode | None = node
        while current is not None and current.move is not None:
            moves.append(current.move)
            current = current.parent
        moves.reverse()
        return tuple(moves)

    def run(self, simulations: int = 160) -> SearchResult:
        if simulations <= 0:
            raise ValueError("simulations must be positive")
        root = SearchNode(position=self.scenario.initial_position())
        self._initialise(root, root=True)

        for _ in range(simulations):
            node = root
            path = [node]
            while True:
                if node.position.terminal:
                    value = self._score(node.position).reward
                    break
                if node.unexpanded is None:
                    self._initialise(node)
                if node.unexpanded is None:
                    raise RuntimeError("search node initialization did not produce moves")
                if node.unexpanded:
                    move = node.unexpanded.pop(0)
                    child = SearchNode(
                        position=self.scenario.apply(
                            node.position, move, self.model.benched_agents
                        ),
                        parent=node,
                        move=move,
                        prior=node.candidate_priors[move.id],
                    )
                    node.children[move.id] = child
                    node = child
                    path.append(node)
                    value = self._evaluate_leaf(node.position)
                    break
                if not node.children:
                    value = self.benchmark.violation_reward
                    break
                node = self._select_child(node)
                path.append(node)

            for visited in path:
                visited.visits += 1
                visited.value_sum += value

        feasible_terminals: list[tuple[SearchNode, ScoreCard]] = []
        for node in self._terminal_nodes(root):
            score = self._score(node.position)
            if score.feasible:
                feasible_terminals.append((node, score))

        if feasible_terminals:
            terminal_node, score = max(
                feasible_terminals,
                key=lambda pair: (
                    pair[1].reward,
                    -pair[0].position.spent_cost,
                    pair[0].visits,
                    tuple(move.id for move in self._path_to(pair[0])),
                ),
            )
            trajectory = self._path_to(terminal_node)
            final_position = terminal_node.position
            abstained = (
                final_position.terminal_status is TerminalStatus.ABSTAINED
            )
        else:
            terminal_node = None
            final_position = self.scenario.safe_abstain()
            trajectory = final_position.trajectory
            score = self._score(final_position)
            abstained = True

        policy_targets: list[PolicyTargetReceipt] = []
        if terminal_node is not None:
            for node in _node_path(terminal_node)[:-1]:
                target = visit_target(node)
                if not target:
                    continue
                legal = self.scenario.legal_moves(
                    node.position, self.model.benched_agents
                )
                policy_targets.append(
                    PolicyTargetReceipt(
                        position=node.position,
                        candidate_hashes=tuple(
                            (move.id, move.content_hash) for move in legal
                        ),
                        target_probabilities=target,
                    )
                )
        frozen_targets = tuple(policy_targets)
        learning_receipt_hash = _experience_digest(
            scenario_manifest_hash=self.scenario.manifest_hash,
            benchmark_profile_hash=self.benchmark.profile_hash,
            model_version=self.model.model_version,
            trajectory=trajectory,
            final_position=final_position,
            score=score,
            policy_targets=frozen_targets,
            abstained=abstained,
        )

        return SearchResult(
            root=root,
            terminal_node=terminal_node,
            trajectory=trajectory,
            final_position=final_position,
            score=score,
            simulations=simulations,
            benchmark_evaluations=self.benchmark_evaluations,
            scenario_version=self.scenario.version,
            scenario_manifest_hash=self.scenario.manifest_hash,
            benchmark_profile_hash=self.benchmark.profile_hash,
            model_version=self.model.model_version,
            abstained=abstained,
            policy_targets=frozen_targets,
            learning_receipt_hash=learning_receipt_hash,
        )


def visit_target(node: SearchNode, temperature: float = 1.0) -> dict[str, float]:
    if not node.children:
        return {}
    if temperature <= 1e-9:
        winner = max(node.children.values(), key=lambda child: child.visits)
        return {
            move_id: 1.0 if child is winner else 0.0
            for move_id, child in node.children.items()
        }
    powers = {
        move_id: max(child.visits, 1) ** (1.0 / temperature)
        for move_id, child in node.children.items()
    }
    total = sum(powers.values())
    return {move_id: value / total for move_id, value in powers.items()}


def _node_path(terminal: SearchNode) -> list[SearchNode]:
    nodes: list[SearchNode] = []
    current: SearchNode | None = terminal
    while current is not None:
        nodes.append(current)
        current = current.parent
    nodes.reverse()
    return nodes


def learn_from_result(
    scenario: Scenario,
    suite: BenchmarkSuite,
    model: PolicyValueModel,
    result: SearchResult,
) -> None:
    """Train only from the immutable, replayed, content-addressed receipt."""

    if result.scenario_version != scenario.version:
        raise ValueError("result scenario version does not match learner scenario")
    if result.scenario_manifest_hash != scenario.manifest_hash:
        raise ValueError("result scenario manifest does not match learner scenario")
    if suite.scenario_manifest_hash != scenario.manifest_hash:
        raise ValueError("benchmark is bound to a different scenario manifest")
    if result.benchmark_profile_hash != suite.profile_hash:
        raise ValueError("result benchmark profile does not match learner benchmark")
    if result.model_version != model.model_version:
        raise ValueError("result was produced by a different policy generation")

    expected_experience_hash = _experience_digest(
        scenario_manifest_hash=result.scenario_manifest_hash,
        benchmark_profile_hash=result.benchmark_profile_hash,
        model_version=result.model_version,
        trajectory=result.trajectory,
        final_position=result.final_position,
        score=result.score,
        policy_targets=result.policy_targets,
        abstained=result.abstained,
    )
    if result.learning_receipt_hash != expected_experience_hash:
        raise ValueError("learning receipt content hash does not match result")

    replayed = scenario.initial_position()
    selected_states: list[Position] = []
    system_abstain = (
        len(result.trajectory) == 1
        and result.trajectory[0].id == "SYSTEM_ABSTAIN"
    )
    if system_abstain:
        replayed = scenario.safe_abstain()
    else:
        for move in result.trajectory:
            selected_states.append(replayed)
            replayed = scenario.apply(replayed, move, model.benched_agents)
    if replayed.state_hash != result.final_position.state_hash:
        raise ValueError("trajectory replay does not match result state")
    replay_score = suite.evaluate(replayed)
    if _digest(_scorecard_payload(replay_score)) != _digest(
        _scorecard_payload(result.score)
    ):
        raise ValueError("benchmark replay does not reproduce the full scorecard")

    actual_abstained = replayed.terminal_status is TerminalStatus.ABSTAINED
    if result.abstained != actual_abstained:
        raise ValueError("result abstention flag does not match terminal state")
    if not actual_abstained and replayed.terminal_status is not TerminalStatus.COMMITTED:
        raise ValueError("non-abstained result lacks an explicit COMMIT")

    selected_by_hash = {position.state_hash: position for position in selected_states}
    seen_target_states: set[str] = set()
    validated_targets: list[
        tuple[Position, tuple[Move, ...], PolicyTargetReceipt]
    ] = []
    for receipt in result.policy_targets:
        state_hash = receipt.position.state_hash
        if state_hash in seen_target_states or state_hash not in selected_by_hash:
            raise ValueError("policy target is duplicate or not on the selected path")
        seen_target_states.add(state_hash)
        canonical_position = selected_by_hash[state_hash]
        legal = scenario.legal_moves(canonical_position, model.benched_agents)
        candidate_hashes = tuple((move.id, move.content_hash) for move in legal)
        if candidate_hashes != receipt.candidate_hashes:
            raise ValueError("policy target candidate manifest does not replay")
        validated_targets.append((canonical_position, legal, receipt))

    # Apply to a challenger copy only after every receipt validates. Publishing
    # the completed generation is one final in-memory transaction.
    challenger = model.frozen_copy()
    for canonical_position, legal, receipt in validated_targets:
        if not system_abstain:
            challenger.learn_policy(legal, receipt.target_probabilities)
        challenger.learn_value(canonical_position, replay_score.reward)

    if not validated_targets:
        challenger.learn_value(scenario.initial_position(), replay_score.reward)
    challenger.generation += 1

    model.policy_weights = dict(challenger.policy_weights)
    model.value_weights = dict(challenger.value_weights)
    model.value_bias = challenger.value_bias
    model.value_updates = challenger.value_updates
    model.generation = challenger.generation
    model.agent_records = challenger.agent_records


def shadow_benchmark_agents(
    scenario: Scenario, suite: BenchmarkSuite, model: PolicyValueModel
) -> None:
    """One scripted receipt per candidate; repeats are not independent evidence."""

    for phase in scenario.phases:
        for move in phase:
            if move.kind is not MoveKind.ABSTAIN:
                model.observe_benchmark(move, suite)


def predicted_greedy_baseline(
    scenario: Scenario, suite: BenchmarkSuite, model: PolicyValueModel | None = None
) -> BaselineResult:
    """Cheap one-path baseline using candidate predictions, then one real score."""

    active_model = (model or PolicyValueModel()).frozen_copy()
    position = scenario.initial_position()
    trajectory: list[Move] = []
    while not position.terminal:
        legal = scenario.legal_moves(position, active_model.benched_agents)
        if not legal:
            abstained = scenario.safe_abstain("Predicted-greedy baseline had no legal move.")
            return BaselineResult(
                trajectory=abstained.trajectory,
                final_position=abstained,
                score=suite.evaluate(abstained),
            )
        move = max(
            legal,
            key=lambda candidate: (
                suite.predicted_move_quality(candidate),
                candidate.id,
            ),
        )
        position = scenario.apply(position, move, active_model.benched_agents)
        trajectory.append(move)
    return BaselineResult(
        trajectory=tuple(trajectory),
        final_position=position,
        score=suite.evaluate(position),
    )


def default_benchmark(scenario: Scenario | None = None) -> BenchmarkSuite:
    bound_scenario = scenario or default_scenario()
    names = ("correctness", "evidence", "safety", "efficiency", "reversibility")

    def values(items: tuple[float, float, float, float, float]) -> Mapping[str, float]:
        return dict(zip(names, items))

    # These are independent synthetic fixture receipts, not agent-authored
    # predictions and not real tool evidence.
    receipts_by_id = {
        "S1": values((0.90, 0.82, 0.94, 0.88, 0.94)),
        "S2": values((0.54, 0.35, 0.70, 0.18, 0.72)),
        "S3": values((0.48, 0.20, 0.35, 0.72, 0.34)),
        "Q1": values((0.88, 0.94, 0.94, 0.74, 0.95)),
        "Q2": values((0.48, 0.22, 0.58, 0.62, 0.70)),
        "Q3": values((0.40, 0.08, 0.38, 0.86, 0.56)),
        "A1": values((0.94, 0.98, 0.96, 0.84, 0.96)),
        "A2": values((0.84, 0.88, 0.91, 0.72, 0.92)),
        "A3": values((0.34, 0.04, 0.26, 0.91, 0.36)),
        "D1": values((0.95, 0.94, 0.97, 0.76, 0.94)),
        "D2": values((0.76, 0.67, 0.84, 0.90, 0.90)),
        "D3": values((0.52, 0.24, 0.43, 0.94, 0.48)),
    }
    moves_by_id = {
        move.id: move for phase in bound_scenario.phases for move in phase
    }
    if set(receipts_by_id) != set(moves_by_id):
        raise ValueError("fixture receipts and scenario candidates do not match")
    receipts = {
        moves_by_id[move_id].content_hash: values
        for move_id, values in receipts_by_id.items()
    }
    return BenchmarkSuite(
        version="software-agent-fixture-v2",
        scenario_manifest_hash=bound_scenario.manifest_hash,
        metrics=(
            BenchmarkMetric("correctness", 0.34),
            BenchmarkMetric("evidence", 0.24, hard_minimum=0.55),
            BenchmarkMetric("safety", 0.20, hard_minimum=0.65),
            BenchmarkMetric("efficiency", 0.12),
            BenchmarkMetric("reversibility", 0.10),
        ),
        receipt_metrics=receipts,
        phase_importance=(0.30, 0.15, 0.30, 0.25),
    )


def _move(
    move_id: str,
    kind: MoveKind,
    actor: str,
    text: str,
    prior: float,
    predicted: tuple[float, float, float, float, float],
    cost: float,
    tags: tuple[str, ...],
    **kwargs: object,
) -> Move:
    metric_names = (
        "correctness",
        "evidence",
        "safety",
        "efficiency",
        "reversibility",
    )
    return Move(
        id=move_id,
        action_key=f"fixture.{move_id.lower()}",
        kind=kind,
        actor=actor,
        text=text,
        base_prior=prior,
        predicted_metrics=dict(zip(metric_names, predicted)),
        cost=cost,
        tags=tags,
        **kwargs,
    )


def default_scenario() -> Scenario:
    return Scenario(
        name="flaky-android-ui-test",
        version="scenario-v2",
        description=(
            "Choose an evidence-efficient recovery plan for a flaky Android UI test "
            "when local, connected-device, and hosted surfaces are available."
        ),
        phases=(
            (
                _move(
                    "S1",
                    MoveKind.PROPOSE,
                    "Scout",
                    "Pin one emulator, reproduce the narrow first failure, classify it, then widen.",
                    0.24,
                    (0.90, 0.82, 0.94, 0.88, 0.94),
                    0.12,
                    ("narrow-first", "classify", "pinned-transport"),
                ),
                _move(
                    "S2",
                    MoveKind.PROPOSE,
                    "Momentum",
                    "Rerun the full local and cloud suites until a pass reveals the likely state.",
                    0.52,
                    (0.62, 0.46, 0.76, 0.42, 0.74),
                    0.55,
                    ("broad-rerun", "retry"),
                ),
                _move(
                    "S3",
                    MoveKind.PROPOSE,
                    "Builder",
                    "Patch the most suspicious selector immediately and validate afterward.",
                    0.24,
                    (0.56, 0.32, 0.52, 0.82, 0.46),
                    0.10,
                    ("guess-patch", "mutation-first"),
                ),
            ),
            (
                _move(
                    "Q1",
                    MoveKind.QUESTION,
                    "Skeptic",
                    "What current artifact distinguishes product failure from harness or transport failure?",
                    0.34,
                    (0.88, 0.94, 0.94, 0.74, 0.95),
                    0.05,
                    ("falsify", "proof-obligation"),
                    opens_question="current-proof",
                ),
                _move(
                    "Q2",
                    MoveKind.QUESTION,
                    "Momentum",
                    "Which observation supports the majority view strongly enough to proceed?",
                    0.46,
                    (0.58, 0.38, 0.66, 0.68, 0.74),
                    0.03,
                    ("majority-vote", "agreement"),
                    opens_question="current-proof",
                ),
                _move(
                    "Q3",
                    MoveKind.QUESTION,
                    "Builder",
                    "What proof, if any, justifies skipping another probe?",
                    0.20,
                    (0.52, 0.24, 0.54, 0.88, 0.60),
                    0.01,
                    ("skip-challenge",),
                    opens_question="current-proof",
                ),
            ),
            (
                _move(
                    "A1",
                    MoveKind.ANSWER,
                    "Verifier",
                    "Run the canonical pinned-device probe and attach the first-failure trace.",
                    0.30,
                    (0.94, 0.98, 0.96, 0.84, 0.96),
                    0.12,
                    ("canonical-probe", "artifact"),
                    requires_question="current-proof",
                    resolves_question="current-proof",
                    evidence_refs=("trace://pinned-emulator/first-failure",),
                ),
                _move(
                    "A2",
                    MoveKind.ANSWER,
                    "Verifier",
                    "Inspect the latest CI trace and compare its environment fingerprint.",
                    0.44,
                    (0.86, 0.90, 0.92, 0.74, 0.92),
                    0.18,
                    ("ci-artifact", "environment-diff"),
                    requires_question="current-proof",
                    resolves_question="current-proof",
                    evidence_refs=("trace://ci/latest", "env://ci/fingerprint"),
                ),
                _move(
                    "A3",
                    MoveKind.ANSWER,
                    "Momentum",
                    "Treat consensus as the answer and proceed without a trusted artifact.",
                    0.26,
                    (0.48, 0.22, 0.48, 0.94, 0.52),
                    0.01,
                    ("unverified-claim", "agreement"),
                    requires_question="current-proof",
                    resolves_question="current-proof",
                    violations=("unverified claim used as proof",),
                ),
            ),
            (
                _move(
                    "D1",
                    MoveKind.COMMIT,
                    "Steward",
                    "Commit only after emulator proof; confirm on one device and hosted automation.",
                    0.28,
                    # The proposer underestimates this expensive-looking move;
                    # independent terminal receipts reveal its higher value.
                    (0.74, 0.65, 0.82, 0.50, 0.82),
                    0.22,
                    ("cross-surface", "proof-gated-commit"),
                    evidence_refs=(
                        "device://connected/confirmation",
                        "cloud://maestro/confirmation",
                    ),
                ),
                _move(
                    "D2",
                    MoveKind.COMMIT,
                    "Builder",
                    "Commit the reversible local-only decision after the narrow proof.",
                    0.48,
                    (0.84, 0.76, 0.88, 0.92, 0.93),
                    0.08,
                    ("local-only", "reversible"),
                ),
                _move(
                    "D3",
                    MoveKind.COMMIT,
                    "Momentum",
                    "Commit now; broad confirmation can run after the decision.",
                    0.24,
                    (0.62, 0.40, 0.56, 0.96, 0.58),
                    0.02,
                    ("commit-before-proof", "speed"),
                    violations=("commit preceded required proof",),
                ),
            ),
        ),
    )


def iter_tree(
    node: SearchNode, max_depth: int = 2
) -> Iterable[tuple[int, SearchNode]]:
    stack: list[tuple[int, SearchNode]] = [(0, node)]
    while stack:
        depth, current = stack.pop()
        yield depth, current
        if depth < max_depth:
            ordered = sorted(
                current.children.values(),
                key=lambda child: (
                    -child.visits,
                    child.move.id if child.move else "",
                ),
            )
            stack.extend((depth + 1, child) for child in reversed(ordered))
