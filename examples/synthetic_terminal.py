#!/usr/bin/env python3
"""Detailed terminal example for the built-in Agent Tree RL fixture."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_tree_rl.engine import (  # noqa: E402
    MoveKind,
    PUCTSearch,
    PolicyValueModel,
    SearchResult,
    TerminalStatus,
    _experience_digest,
    default_benchmark,
    default_scenario,
    iter_tree,
    learn_from_result,
    predicted_greedy_baseline,
    shadow_benchmark_agents,
)


BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RESET = "\x1b[0m"


def heading(text: str) -> str:
    return f"{BOLD}{text}{RESET}"


def render_result(result: SearchResult, max_depth: int = 2) -> str:
    lines = [
        heading("SEARCH RECEIPT"),
        f"simulations: {result.simulations}",
        f"benchmark evaluations (cache misses): {result.benchmark_evaluations}",
        f"scenario: {result.scenario_version}",
        f"benchmark: {result.benchmark_profile_hash[:12]}",
        f"policy: {result.model_version}",
        f"root state: {result.root.position.state_hash[:12]}",
        f"selected: {' -> '.join(move.id for move in result.trajectory)}",
        f"terminal: {result.final_position.terminal_status.value}",
        f"reward: {result.score.reward:+.3f}",
        f"feasible: {result.score.feasible}",
        f"cost penalty: {result.score.cost_penalty:.3f}",
        "metrics: "
        + ", ".join(
            f"{name}={value:.3f}" for name, value in result.score.metrics.items()
        ),
        "evidence: " + (", ".join(result.final_position.evidence_refs) or "<none>"),
    ]
    if result.score.gate_failures:
        lines.append("gate failures: " + "; ".join(result.score.gate_failures))

    lines.extend(["", heading(f"TREE (through depth {max_depth})")])
    for depth, node in iter_tree(result.root, max_depth=max_depth):
        label = (
            "ROOT"
            if node.move is None
            else f"{node.move.id} {node.move.kind.value} @{node.move.actor}"
        )
        lines.append(
            f"{'  ' * depth}{label:<33} N={node.visits:<4} Q={node.q_value:+.3f} "
            f"P={node.prior:.3f} state={node.position.state_hash[:12]}"
        )

    lines.extend(["", heading("SELECTED SEARCHED PATH")])
    for ply, move in enumerate(result.trajectory, start=1):
        evidence = (
            f" evidence={','.join(move.evidence_refs)}" if move.evidence_refs else ""
        )
        lines.append(
            f"{ply}. [{move.id}] {move.kind.value:<8} {move.actor:<12} "
            f"{move.text}{evidence}"
        )
    return "\n".join(lines)


def render_model(model: PolicyValueModel) -> str:
    snapshot = model.snapshot()
    lines = [heading("LEARNED OVERLAY (bounded; evaluator unchanged)")]
    lines.append(f"model: {snapshot['model_version']}")
    policy = snapshot["policy_weights"]
    lines.append(
        "policy: "
        + (
            ", ".join(f"{tag}={value:+.3f}" for tag, value in policy.items())
            or "<cold start>"
        )
    )
    lines.append(
        f"value updates: {snapshot['value_updates']}  "
        f"value bias: {snapshot['value_bias']:+.3f}"
    )
    lines.append("agents (synthetic fixture status only):")
    agents = snapshot["agents"]
    if not agents:
        lines.append("  <no scripted benchmark observations>")
    for actor, record in agents.items():
        lines.append(
            f"  {actor:<10} pseudo_n={record['samples']:>5.1f} "
            f"mean={record['mean']:.3f} upper={record['upper_confidence']:.3f} "
            f"{record['status']}"
        )
    return "\n".join(lines)


def run_episode(
    model: PolicyValueModel,
    simulations: int,
    seed: int,
    explore: bool,
) -> SearchResult:
    scenario = default_scenario()
    search = PUCTSearch(
        scenario,
        default_benchmark(scenario),
        model,
        seed=seed,
        root_noise_fraction=0.18 if explore else 0.0,
    )
    return search.run(simulations=simulations)


def prove_invariants(result: SearchResult, model: PolicyValueModel) -> list[str]:
    checks = {
        "terminal trajectory contains four canonical plies": len(result.trajectory)
        == 4,
        "selected path ends in explicit COMMIT": result.trajectory[-1].kind
        is MoveKind.COMMIT,
        "selected path passes every hard gate": result.score.feasible,
        "reward is normalized to [-1, 1]": -1.0
        <= result.score.reward
        <= 1.0,
        "visit accounting matches simulation budget": result.root.visits
        == result.simulations,
        "policy weights remain bounded": all(
            abs(weight) <= model.policy_limit
            for weight in model.policy_weights.values()
        ),
        "benchmark profile remains content-addressed": len(
            result.benchmark_profile_hash
        )
        == 64,
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise RuntimeError("proof failed: " + "; ".join(failures))
    return list(checks)


def verify() -> int:
    """Narrow executable proof plus adversarial regression probes."""

    scenario = default_scenario()
    suite = default_benchmark(scenario)
    cold_model = PolicyValueModel()
    frozen_before = cold_model.snapshot()
    first = run_episode(cold_model, 256, seed=7, explore=False)
    second = run_episode(cold_model, 256, seed=7, explore=False)
    frozen_after = cold_model.snapshot()
    baseline = predicted_greedy_baseline(scenario, suite, cold_model)

    checks: list[tuple[str, bool]] = [
        (
            "same seed reproduces path, state, and reward",
            [move.id for move in first.trajectory]
            == [move.id for move in second.trajectory]
            and first.final_position.state_hash == second.final_position.state_hash
            and first.score.reward == second.score.reward,
        ),
        ("search does not mutate the live learned overlay", frozen_before == frozen_after),
        (
            "PUCT overturns the misleading highest prior",
            max(scenario.phases[0], key=lambda move: move.base_prior).id == "S2"
            and first.trajectory[0].id == "S1",
        ),
        (
            "PUCT beats the cheap predicted-greedy path after spending more evaluations",
            first.score.reward > baseline.score.reward
            and first.benchmark_evaluations > 1,
        ),
        ("selected path is hard-gate feasible", first.score.feasible),
        (
            "selected path ends only through explicit COMMIT",
            first.final_position.terminal_status is TerminalStatus.COMMITTED
            and first.trajectory[-1].kind is MoveKind.COMMIT,
        ),
        (
            "reported path contains only nodes actually expanded by search",
            first.terminal_node is not None
            and all(
                move.id in node.children
                for move, node in zip(
                    first.trajectory,
                    _selected_nodes(first),
                )
            ),
        ),
    ]

    # Canonical move binding: a same-ID forged payload must never be applied.
    canonical_s1 = scenario.phases[0][0]
    forged = replace(
        canonical_s1,
        actor="Attacker",
        cost=0.0,
        evidence_refs=("fabricated://proof",),
    )
    forged_rejected = False
    try:
        scenario.apply(scenario.initial_position(), forged)
    except ValueError:
        forged_rejected = True
    checks.append(("same-ID forged move payload is rejected", forged_rejected))

    altered_canonical = replace(
        canonical_s1,
        action_key="prod.delete",
        actor="Attacker",
        text="Delete production before diagnosis.",
    )
    altered_scenario = replace(
        scenario,
        version="scenario-forged-manifest",
        phases=(
            (altered_canonical,) + scenario.phases[0][1:],
            scenario.phases[1],
            scenario.phases[2],
            scenario.phases[3],
        ),
    )
    manifest_mismatch_rejected = False
    try:
        PUCTSearch(altered_scenario, suite, PolicyValueModel())
    except ValueError:
        manifest_mismatch_rejected = True
    checks.append(
        (
            "benchmark receipts reject changed canonical scenario content",
            manifest_mismatch_rejected,
        )
    )

    immutable = False
    try:
        canonical_s1.predicted_metrics["correctness"] = 0.0  # type: ignore[index]
    except TypeError:
        immutable = True
    checks.append(("nested move metric mapping is deeply immutable", immutable))

    canonical_position = scenario.apply(scenario.initial_position(), canonical_s1)
    changed_cost = replace(canonical_position, spent_cost=999.0)
    checks.append(
        (
            "state digest changes when decision-relevant cost changes",
            canonical_position.state_hash != changed_cost.state_hash
            and len(canonical_position.state_hash) == 64,
        )
    )

    # Every answer must target the same currently open question it resolves.
    impossible_answer_state = replace(
        canonical_position, phase=2, open_questions=()
    )
    all_answers_rejected = True
    for answer in scenario.phases[2]:
        try:
            scenario.apply(impossible_answer_state, answer)
            all_answers_rejected = False
        except ValueError:
            pass
    checks.append(
        ("all answers are illegal when no matching question is open", all_answers_rejected)
    )

    # The intentionally unsafe fast path is structurally legal but infeasible.
    unsafe = scenario.initial_position()
    for move_id in ("S3", "Q3", "A3", "D3"):
        move = next(
            move for phase in scenario.phases for move in phase if move.id == move_id
        )
        unsafe = scenario.apply(unsafe, move)
    unsafe_score = suite.evaluate(unsafe)
    checks.extend(
        [
            ("trusted hard-gate receipt dominates soft speed", not unsafe_score.feasible),
            (
                "unsafe path receives the governed floor reward",
                unsafe_score.reward == suite.violation_reward,
            ),
        ]
    )

    proofless = replace(first.final_position, evidence_refs=())
    checks.append(
        ("a committed path without trusted evidence fails closed", not suite.evaluate(proofless).feasible)
    )

    one_simulation = run_episode(PolicyValueModel(), 1, seed=7, explore=False)
    checks.append(
        (
            "insufficient search returns explicit safe abstention, never an infeasible PV",
            one_simulation.abstained
            and one_simulation.final_position.terminal_status
            is TerminalStatus.ABSTAINED
            and one_simulation.score.feasible,
        )
    )

    invalid_profile_rejected = False
    try:
        replace(suite, cost_weight=-10.0, violation_reward=1.0)
    except ValueError:
        invalid_profile_rejected = True
    checks.append(("malformed benchmark configuration fails closed", invalid_profile_rejected))

    empty_trust_prefix_rejected = False
    try:
        replace(suite, trusted_evidence_prefixes=("",))
    except ValueError:
        empty_trust_prefix_rejected = True
    checks.append(
        ("empty or unapproved evidence trust prefixes are rejected", empty_trust_prefix_rejected)
    )

    poisoned_target_rejected = False
    try:
        PolicyValueModel().learn_policy(
            scenario.phases[0],
            {"S1": float("nan"), "S2": 0.0, "S3": 0.0},
        )
    except ValueError:
        poisoned_target_rejected = True
    checks.append(("non-finite policy target is rejected", poisoned_target_rejected))

    poisoned_value_rate_rejected = False
    try:
        PolicyValueModel().learn_value(
            scenario.initial_position(), 0.5, learning_rate=float("nan")
        )
    except ValueError:
        poisoned_value_rate_rejected = True
    checks.append(
        ("non-finite value learning rate is rejected", poisoned_value_rate_rejected)
    )

    mismatched_profile_rejected = False
    try:
        learn_from_result(
            scenario,
            replace(suite, version="incompatible-profile"),
            PolicyValueModel(),
            first,
        )
    except ValueError:
        mismatched_profile_rejected = True
    checks.append(("reward-profile mixing is rejected", mismatched_profile_rejected))

    # Learning consumes immutable target receipts, never mutable display-tree nodes.
    first.root.children["S3"].visits = 1_000_000_000
    mutated_tree_model = PolicyValueModel()
    clean_tree_model = PolicyValueModel()
    learn_from_result(scenario, suite, mutated_tree_model, first)
    learn_from_result(scenario, suite, clean_tree_model, second)
    checks.append(
        (
            "post-search tree mutation cannot poison immutable learning targets",
            mutated_tree_model.policy_weights == clean_tree_model.policy_weights
            and mutated_tree_model.value_weights == clean_tree_model.value_weights
            and mutated_tree_model.value_bias == clean_tree_model.value_bias,
        )
    )

    bad_second = replace(
        first.policy_targets[1],
        candidate_hashes=(
            (first.policy_targets[1].candidate_hashes[0][0], "0" * 64),
        )
        + first.policy_targets[1].candidate_hashes[1:],
    )
    bad_targets = (
        first.policy_targets[0],
        bad_second,
    ) + first.policy_targets[2:]
    bad_receipt_hash = _experience_digest(
        scenario_manifest_hash=first.scenario_manifest_hash,
        benchmark_profile_hash=first.benchmark_profile_hash,
        model_version=first.model_version,
        trajectory=first.trajectory,
        final_position=first.final_position,
        score=first.score,
        policy_targets=bad_targets,
        abstained=first.abstained,
    )
    transactional_model = PolicyValueModel()
    transactional_before = transactional_model.snapshot()
    late_receipt_rejected = False
    try:
        learn_from_result(
            scenario,
            suite,
            transactional_model,
            replace(
                first,
                policy_targets=bad_targets,
                learning_receipt_hash=bad_receipt_hash,
            ),
        )
    except ValueError:
        late_receipt_rejected = True
    checks.append(
        (
            "late invalid target rejection is transactionally model-safe",
            late_receipt_rejected
            and transactional_model.snapshot() == transactional_before,
        )
    )

    tampered_abstention_rejected = False
    tampered_score = replace(one_simulation.score, reward=1.0)
    try:
        learn_from_result(
            scenario,
            suite,
            PolicyValueModel(),
            replace(one_simulation, score=tampered_score),
        )
    except ValueError:
        tampered_abstention_rejected = True
    checks.append(
        ("abstention reward tampering fails benchmark replay", tampered_abstention_rejected)
    )

    system_fallback_model = PolicyValueModel()
    learn_from_result(
        scenario, suite, system_fallback_model, one_simulation
    )
    checks.append(
        (
            "insufficient-search SYSTEM_ABSTAIN never trains policy",
            not system_fallback_model.policy_weights
            and system_fallback_model.value_updates == 1,
        )
    )

    explicit_abstain = replace(
        scenario.phases[3][0],
        action_key="fixture.explicit-abstain",
        kind=MoveKind.ABSTAIN,
        text="Abstain because no authorized commit is available.",
        evidence_refs=(),
    )
    abstain_scenario = replace(
        scenario,
        version="scenario-explicit-abstain",
        phases=(
            scenario.phases[0],
            scenario.phases[1],
            scenario.phases[2],
            (explicit_abstain,),
        ),
    )
    abstain_suite = replace(
        suite, scenario_manifest_hash=abstain_scenario.manifest_hash
    )
    explicit_model = PolicyValueModel()
    explicit_result = PUCTSearch(
        abstain_scenario, abstain_suite, explicit_model, seed=7
    ).run(64)
    learn_from_result(
        abstain_scenario, abstain_suite, explicit_model, explicit_result
    )
    unsafe_abstain_position = abstain_scenario.initial_position()
    for move_id in ("S3", "Q3", "A3"):
        move = next(
            move
            for phase in abstain_scenario.phases
            for move in phase
            if move.id == move_id
        )
        unsafe_abstain_position = abstain_scenario.apply(
            unsafe_abstain_position, move
        )
    unsafe_abstain_position = abstain_scenario.apply(
        unsafe_abstain_position, explicit_abstain
    )
    unsafe_abstain_score = abstain_suite.evaluate(unsafe_abstain_position)
    checks.append(
        (
            "searched explicit ABSTAIN is labeled and policy-learned",
            explicit_result.abstained
            and explicit_result.final_position.terminal_status
            is TerminalStatus.ABSTAINED
            and explicit_model.generation == 1
            and bool(explicit_model.policy_weights),
        )
    )
    checks.append(
        (
            "searched ABSTAIN preserves branch cost and warnings",
            unsafe_abstain_score.feasible
            and unsafe_abstain_score.cost_penalty > 0.0
            and bool(unsafe_abstain_score.gate_failures)
            and unsafe_abstain_score.reward < abstain_suite.abstain_reward,
        )
    )

    seed_zero = run_episode(PolicyValueModel(), 44, seed=0, explore=False)
    terminal_rewards: list[float] = []
    stack = [seed_zero.root]
    while stack:
        node = stack.pop()
        if node.position.terminal:
            score = suite.evaluate(node.position)
            if score.feasible:
                terminal_rewards.append(score.reward)
        stack.extend(node.children.values())
    checks.append(
        (
            "commit selection prefers governed reward over terminal visit count",
            bool(terminal_rewards)
            and seed_zero.score.reward == max(terminal_rewards),
        )
    )

    # Whole-path learning and durable synthetic bench transition.
    model = PolicyValueModel()
    for episode in range(12):
        result = run_episode(model, 128, seed=200 + episode, explore=True)
        learn_from_result(scenario, suite, model, result)
        shadow_benchmark_agents(scenario, suite, model)
    post_bench = run_episode(model, 128, seed=999, explore=False)
    cold_low_budget = run_episode(PolicyValueModel(), 16, seed=7, explore=False)
    learned_low_budget = run_episode(model, 16, seed=7, explore=False)
    momentum_record = model.record_for("Momentum")
    for _ in range(40):
        momentum_record.observe(1.0)
    checks.extend(
        [
            (
                "all learned policy coordinates remain clipped",
                all(
                    abs(value) <= model.policy_limit
                    for value in model.policy_weights.values()
                ),
            ),
            (
                "whole selected discussion path emits policy features",
                "falsify" in model.policy_weights
                and "cross-surface" in model.policy_weights,
            ),
            (
                "scripted weak agent enters durable BENCHED state",
                model.is_benched("Momentum"),
            ),
            (
                "benched agent remains absent from live root expansion",
                "S2" not in post_bench.root.children,
            ),
            (
                "new observations cannot silently reactivate a benched agent",
                model.is_benched("Momentum"),
            ),
            (
                "scripted strong verifier remains active",
                not model.is_benched("Verifier"),
            ),
            (
                "learned controller improves equal-budget fixture outcome",
                cold_low_budget.abstained
                and not learned_low_budget.abstained
                and learned_low_budget.score.reward > cold_low_budget.score.reward,
            ),
        ]
    )

    failed = [name for name, passed in checks if not passed]
    print(heading("AGENT TREE RL — ADVERSARIAL NARROW PROOF"))
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    if failed:
        print("\nFailed: " + "; ".join(failed))
        return 1
    print(f"\nPUCT:    {' -> '.join(move.id for move in first.trajectory)}")
    print(
        f"          reward={first.score.reward:+.3f}, "
        f"benchmark_evals={first.benchmark_evaluations}"
    )
    print(f"GREEDY:  {' -> '.join(move.id for move in baseline.trajectory)}")
    print(f"          reward={baseline.score.reward:+.3f}, evals=1")
    print(
        f"16-SIM:   cold={cold_low_budget.score.reward:+.3f} "
        f"learned={learned_low_budget.score.reward:+.3f}"
    )
    print(f"BENCHED: {sorted(model.benched_agents)} (scripted fixture only)")
    return 0


def _selected_nodes(result: SearchResult) -> list[object]:
    """Return parent nodes for each selected edge, for proof display only."""

    nodes = []
    node = result.root
    for move in result.trajectory:
        nodes.append(node)
        child = node.children.get(move.id)
        if child is None:
            break
        node = child
    return nodes


def demo(simulations: int = 256, training_episodes: int = 12) -> int:
    scenario = default_scenario()
    suite = default_benchmark(scenario)
    model = PolicyValueModel()
    baseline = predicted_greedy_baseline(scenario, suite, model)
    initial = run_episode(model, simulations, seed=7, explore=False)
    before = model.priors(scenario.phases[0])

    for episode in range(training_episodes):
        result = run_episode(
            model, max(64, simulations // 2), seed=100 + episode, explore=True
        )
        learn_from_result(scenario, suite, model, result)
        shadow_benchmark_agents(scenario, suite, model)

    final = run_episode(model, simulations, seed=7, explore=False)
    after = model.priors(
        scenario.legal_moves(scenario.initial_position(), model.benched_agents)
    )
    checks = prove_invariants(final, model)

    print(heading("AGENT TREE RL — DETERMINISTIC FIXTURE"))
    print(f"scenario: {scenario.description}")
    print(f"benchmark: {suite.version} / {suite.profile_hash[:12]}")
    print("candidate predictions and terminal benchmark receipts are separate fixtures")
    print()
    print(heading("CHEAP PREDICTED-GREEDY BASELINE"))
    print(f"path: {' -> '.join(move.id for move in baseline.trajectory)}")
    print(f"reward after one terminal evaluation: {baseline.score.reward:+.3f}")
    print()
    print(heading("COLD-START ROOT PRIORS"))
    print(json.dumps(before, indent=2, sort_keys=True))
    print()
    print(render_result(initial))
    print()
    print(heading(f"AFTER {training_episodes} SCRIPTED CHALLENGER EPISODES"))
    print(json.dumps(after, indent=2, sort_keys=True))
    print(render_model(model))
    print()
    print(render_result(final))
    print()
    print(heading("PROOF CONTRACT"))
    for check in checks:
        print(f"PASS  {check}")
    return 0


def train(episodes: int, simulations: int) -> int:
    model = PolicyValueModel()
    scenario = default_scenario()
    suite = default_benchmark(scenario)
    for episode in range(episodes):
        result = run_episode(model, simulations, seed=1000 + episode, explore=True)
        learn_from_result(scenario, suite, model, result)
        shadow_benchmark_agents(scenario, suite, model)
        print(
            f"episode={episode + 1:02d} selected={result.trajectory[0].id} "
            f"reward={result.score.reward:+.3f} benched={sorted(model.benched_agents)}"
        )
    print()
    print(render_model(model))
    return 0


def interactive(simulations: int) -> int:
    model = PolicyValueModel()
    last: SearchResult | None = None
    episode = 0
    while True:
        print("\033[2J\033[H", end="")
        print(heading("AGENT TREE RL — SYNTHETIC CONTROLLER LAB"))
        print(DIM + default_scenario().description + RESET)
        print()
        print(render_model(model))
        if last is not None:
            print()
            print(render_result(last, max_depth=1))
        print()
        print(
            f"{BOLD}[d]{RESET} deterministic search  "
            f"{BOLD}[t]{RESET} train one episode  "
            f"{BOLD}[b]{RESET} scripted shadow bench  "
            f"{BOLD}[r]{RESET} reset  "
            f"{BOLD}[q]{RESET} quit"
        )
        command = input("> ").strip().lower()[:1]
        if command == "q":
            return 0
        if command == "d":
            last = run_episode(model, simulations, seed=7, explore=False)
        elif command == "t":
            episode += 1
            last = run_episode(model, simulations, seed=episode, explore=True)
            learn_from_result(default_scenario(), default_benchmark(), model, last)
        elif command == "b":
            shadow_benchmark_agents(
                default_scenario(), default_benchmark(), model
            )
        elif command == "r":
            model = PolicyValueModel()
            last = None
            episode = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo", help="run the deterministic fixture")
    demo_parser.add_argument("--simulations", type=int, default=256)
    demo_parser.add_argument("--episodes", type=int, default=12)

    train_parser = subparsers.add_parser("train", help="watch bounded learning")
    train_parser.add_argument("--simulations", type=int, default=128)
    train_parser.add_argument("--episodes", type=int, default=12)

    interactive_parser = subparsers.add_parser(
        "interactive", help="drive state by hand"
    )
    interactive_parser.add_argument("--simulations", type=int, default=128)
    subparsers.add_parser("verify", help="run adversarial regression probes")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    command = args.command
    if command is None:
        command = "interactive" if sys.stdin.isatty() else "demo"
    if command == "demo":
        return demo(args.simulations, args.episodes)
    if command == "train":
        return train(args.episodes, args.simulations)
    if command == "verify":
        return verify()
    return interactive(args.simulations)


if __name__ == "__main__":
    raise SystemExit(main())
