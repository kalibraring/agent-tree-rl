# Agent Tree RL

[![CI](https://github.com/kalibraring/agent-tree-rl/actions/workflows/ci.yml/badge.svg)](https://github.com/kalibraring/agent-tree-rl/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Turn structured multi-agent deliberation into auditable decisions, then promote
routing policies only when independent benchmarks prove improvement.

Agent Tree RL is an experimental, production-oriented reference implementation.
It models proposals, questions, answers, and commits as chess-like moves; searches
them with constraint-first PUCT; records authenticated evidence; trains immutable
challengers offline; and promotes or rolls them back through explicit gates.

> **Maturity: public alpha (`v0.1`).** The repository proves the controller and
> security mechanics against a synthetic Android decision fixture. It does not
> yet call real agents or accept user-defined scenario manifests. Do not use it
> for privileged or irreversible actions without completing the product and
> environment gates in [the implementation status](docs/IMPLEMENTATION_STATUS.md).

## See it in one minute

Python 3.11 or newer is required.
The runtime and evidence-worker security model currently supports POSIX systems
(Linux and macOS); Windows is not a supported service target in `v0.1`.

```bash
git clone https://github.com/kalibraring/agent-tree-rl.git
cd agent-tree-rl
python3 -m agent_tree_rl.cli demo
```

The demo prints the searched proposal -> question -> answer -> commit path,
hard-gate result, and reward. It creates no state and calls no external agent or
tool. Machine-readable output is available with `--json`.

Expected shape:

```text
Agent Tree RL synthetic demo
fixture: flaky-android-ui-test
selected path:
  1. S1 [PROPOSE] ...
  2. Q1 [QUESTION] ...
  3. A1 [ANSWER] ...
  4. D1 [COMMIT] ...
status: COMMITTED
hard gates: pass
Synthetic fixture only; no external agents or tools were called.
```

For the authenticated service walkthrough, follow the
[usage guide](docs/USAGE_GUIDE.md).

## What it proves

- Typed, canonical proposal/question/answer/commit transitions.
- Hard constraints that run before scalar reward.
- PUCT search with safe abstention when no proven path exists.
- Authenticated, replay-protected experience and evidence receipts.
- Tenant-scoped RBAC, budgets, idempotency, and fenced training leases.
- Immutable challenger artifacts and paired hidden champion/challenger gates.
- Atomic promotion, audited rollback, and authenticated backup/restore.
- Fail-closed configuration and bounded subprocess evidence execution.

## Use it when

- you are designing an auditable controller for costly agent decisions;
- safety or correctness gates must dominate popularity or predicted reward;
- learned routing must change offline through reviewable artifacts;
- you need a concrete reference for receipts, promotion, rollback, and recovery.

## Do not use it yet when

- you need a drop-in framework that invokes real model providers;
- users must submit arbitrary tasks or decision-tree manifests;
- you need multi-writer horizontal scale or a hosted control plane;
- you need proof that this synthetic learner improves real agents;
- an action is privileged, irreversible, or safety-critical.

Those are product milestones, not hidden capabilities. See [ROADMAP.md](ROADMAP.md).

## How the controller works

```text
structured position
        |
        v
legal typed moves -> hard constraints -> PUCT search -> commit or abstain
                                                |
                                                v
                                  authenticated experience
                                                |
                         offline train -> hidden paired evaluation
                                                |
                              atomic promote or audited rollback
```

The learner cannot rewrite the legal moves, benchmark, evidence policy, or
promotion rules. It only produces a bounded immutable policy overlay.

## Install the CLI

For an isolated local installation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/agent-tree-rl --version
.venv/bin/agent-tree-rl demo
```

The project intentionally has no runtime Python dependencies. Release artifacts
are built as a wheel and source archive; PyPI publication is not enabled yet.

## Verify a checkout

Run the narrow product proof first:

```bash
python3 -m agent_tree_rl.cli demo --json
```

Run the controller acceptance proof:

```bash
python3 -m agent_tree_rl.cli verify
```

Run the complete release preflight, including tests and clean wheel/source installs:

```bash
.venv/bin/python -m pip install -e ".[dev]"
PYTHON=.venv/bin/python scripts/verify_release.sh
```

`verify` proves controller and repository mechanics on disposable local state.
It cannot attest cloud IAM, a proprietary hidden benchmark, independent workers,
TLS ingress, or an off-site backup system.

## Documentation

| Read this | When you need |
|---|---|
| [Usage guide](docs/USAGE_GUIDE.md) | Authenticated local service and lifecycle walkthrough |
| [API reference](docs/API.md) | Routes, roles, payloads, and idempotency |
| [Architecture](docs/ARCHITECTURE.md) | Components, trust boundaries, and lifecycle |
| [Threat model](docs/THREAT_MODEL.md) | Assets, threats, controls, and residual risk |
| [Implementation status](docs/IMPLEMENTATION_STATUS.md) | Implemented, reference-only, and blocked claims |
| [Product and open-source plan](docs/PROJECT_PLAN.md) | Launch checklist and product milestones |
| [Production runbook](docs/RUNBOOK.md) | Deployment, backup, restore, rotation, and incidents |
| [Technical design](docs/TECHNICAL_DESIGN.md) | Full design rationale and edge-case analysis |

## Project policies

- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)

## License

Agent Tree RL is available under the [MIT License](LICENSE).
