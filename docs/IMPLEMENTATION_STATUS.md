# Implementation status

Agent Tree RL `v0.1` is an experimental, production-oriented reference
implementation. It is not a general agent platform and is not approved for
privileged or irreversible production actions.

This matrix separates three facts that earlier design prose could blur.

## Implemented and executable

| Surface | Current evidence |
|---|---|
| Decision model | Canonical typed moves, immutable positions, hard constraints, bounded PUCT, safe abstention |
| Built-in fixture | Synthetic `flaky-android-ui-test` scenario and public sample benchmark |
| Bounded learning | Offline immutable challenger; learned overlay cannot alter governance |
| Identity and tenancy | Hashed bearer tokens, distinct subjects, strict role matrix, tenant-scoped records |
| Receipts | Purpose/tenant/key/nonce/expiry binding, signatures, replay claims, freshness checks |
| Evidence execution | Server-owned command IDs, no shell, bounded args/output/time/environment/working roots |
| Durable control | SQLite WAL, migrations, transactions, idempotency, budgets, fenced leases, append-only audit |
| Promotion | Artifact-bound hidden receipts, absolute threshold, paired non-regression, separation of duties, atomic CAS |
| Recovery | Content-addressed objects, authenticated bounded bundle, fresh-root restore, resume marker, rollback, fail-closed interrupted-operation reconciliation |
| Operations | SIGTERM admission gate, bounded drain plus owned-process-group cancellation/reaping, separate bounded probe capacity, single-service runtime lock, cheap readiness, fixed-cardinality route metrics, structured logs, backup, rotation, Compose/systemd/Caddy examples |
| Public project | Demo, package metadata, community policies, public-release scanner, CI and tag release workflow |

Run:

```bash
python3 -m agent_tree_rl.cli demo --json
python3 -m agent_tree_rl.cli verify
scripts/verify_release.sh
```

## Reference-only boundaries

These implementations prove mechanics inside one trusted checkout; they do not
prove the corresponding real-world claim.

| Reference surface | What it does not prove |
|---|---|
| Synthetic scenario | Improvement on a user's tasks or agents |
| Public sample benchmark | Secrecy, representativeness, or independent governance |
| Local HMAC benchmark worker | Independence from a compromised controller |
| File-backed bearer tokens | Production identity, revocation service, or workload attestation |
| Built-in HTTP server | Safe direct internet exposure or resistance to connection-layer exhaustion |
| Single SQLite writer | Multi-writer horizontal availability |
| Local Compose/systemd examples | Cloud IAM, network, storage, image, or secret-manager correctness |
| Repository acceptance proof | Target-environment SLO, canary, restore, RPO, or RTO evidence |

## Product work required

- Versioned user-defined scenario/tree manifests.
- Stable move, transition, constraint, score, and artifact contracts.
- Real agent/provider and evidence-worker adapters.
- CLI/API surfaces for custom submit, inspect, cancel, and replay-safe execution.
- OpenAPI/JSON Schema and compatibility/deprecation policy.
- Product observability and real baseline/outcome measurement.
- External-user quickstart and two production-shaped pilot workloads.

Track these milestones in [../ROADMAP.md](../ROADMAP.md).

## Environment-owned production gates

- Proprietary, independently governed hidden suite and signing identity.
- Disposable workers with no controller DB, secret mounts, host sockets, metadata
  service, or default network egress.
- Workload identity, KMS/secret delivery, TLS/mTLS, edge timeouts and rate limits.
- Immutable remote audit, monitored queues/storage, and incident ownership.
- Digest-pinned images, dependency policy, SBOM, provenance, scanning, and
  signatures.
- Off-site encrypted backup, restore drill, canary, rollback, RPO, and RTO
  evidence on the actual release candidate.

Every production gate remains blocking until dated evidence exists. The complete
evidence checklist is [PRODUCTION_CHECKLIST.md](PRODUCTION_CHECKLIST.md).
