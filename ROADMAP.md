# Roadmap

The roadmap advances from an honest reference implementation to a usable agent
product. Dates are intentionally absent until each milestone has an owner and
evidence plan.

## `v0.1` — governed controller reference

- [x] Typed deterministic decision moves and constraint-first PUCT.
- [x] Synthetic decision, evidence, learning, evaluation, promotion, rollback,
  and recovery lifecycle.
- [x] Authenticated receipts, tenant boundaries, budgets, leases, audit, and
  content-addressed policy artifacts.
- [x] Public alpha packaging, one-command demo, CI, security policy, and
  contributor documentation.

## `v0.2` — user-defined decisions

- [ ] Versioned scenario/tree manifest with JSON Schema.
- [ ] Stable legal-move, transition, constraint, and score contracts.
- [ ] `validate`, `run`, and `inspect` CLI commands for user scenarios.
- [ ] One custom-scenario tutorial that requires no core source edits.
- [ ] Golden compatibility tests for manifest and artifact versions.

Success means an outside user can model and run a new decision without editing
`agent_tree_rl/engine.py` or `agent_tree_rl/control.py`.

## `v0.3` — real agent adapters

- [ ] Typed agent request/response and capability contracts.
- [ ] Deterministic fake adapter and one real provider-neutral adapter example.
- [ ] Evidence-worker adapter with attestation metadata.
- [ ] Sandboxed worker boundary with denied controller secrets and default
  network egress.
- [ ] Cost, latency, cancellation, and partial-outcome accounting.

Success means the same scenario can compare frozen real-agent configurations
against a deterministic baseline.

## `v0.5` — deployable beta

- [ ] OpenAPI document and generated compatibility checks.
- [ ] Durable asynchronous queue and cancellation.
- [ ] OIDC/workload identity option.
- [ ] Route-template metrics, latency histograms, queue and budget gauges,
  backup age, and outcome dashboards.
- [ ] PostgreSQL/shared-store design for multiple application writers.
- [ ] Two pilot workloads, seven-day soak, restore drill, and bad-promotion drill.

## `v1.0` — stable product

`v1.0` requires stable scenario, adapter, HTTP, artifact, and migration contracts;
independent private evaluation in the target environment; supply-chain and
recovery evidence; a compatibility/deprecation policy; and successful operation
by at least one external team.

## Product measure

The primary measure is independently verified successful decisions per unit
cost relative to a frozen baseline. Supporting measures include appropriate
abstention, benchmark coverage, regression rejection, rollback recovery time,
time to first custom scenario, and active external scenarios.

The project does not collect phone-home telemetry by default.
