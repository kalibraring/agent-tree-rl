# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) while public contracts remain in alpha.

## [Unreleased]

### Planned

- Versioned user-defined scenario manifests.
- Real agent and evidence-worker adapter contracts.
- OpenAPI and JSON Schema definitions.

## [0.1.0] - 2026-07-17

### Added

- Constraint-first PUCT over typed proposal, question, answer, and commit moves.
- Safe abstention, bounded offline learning, and immutable policy artifacts.
- Authenticated experience, evidence, and benchmark receipts with replay defense.
- Tenant-scoped RBAC, budgets, idempotency, fenced leases, and append-only audit.
- Hidden paired evaluation, atomic promotion, rollback, and backup/restore.
- One-command synthetic demo, authenticated HTTP service, diagnostics, and
  release verification.
- SIGTERM readiness gating and bounded work drain, separately bounded probe
  capacity, exclusive single-service ownership, and crash reconciliation.
- Threat model, runbook, product roadmap, contributor policy, and CI/release
  automation.

### Security

- Fail-closed secret files and public-sample benchmark handling.
- Bounded subprocess execution with no shell command surface.
- Fixed-cardinality route labels and cheap readiness checks.
- Fail-closed interrupted idempotency recovery that releases only reserved
  budget, preserves consumed spend, fences inherited leases, and retains
  ambiguous crash keys as non-expiring tombstones.
- Exact service-owned process-group registration and deadline cancellation for
  evidence and nested hidden-benchmark workers before runtime-lock release.
- One-time bootstrap bearer tokens are written to an exclusive mode-`0600` file
  and never emitted to stdout; initialization rolls back partial secret state.
- Digest-pinned container base, hash-locked CI tooling, least-privilege release
  jobs, SPDX SBOM, archive checksums, and signed build-provenance attestations.

[Unreleased]: https://github.com/kalibraring/agent-tree-rl/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kalibraring/agent-tree-rl/releases/tag/v0.1.0
