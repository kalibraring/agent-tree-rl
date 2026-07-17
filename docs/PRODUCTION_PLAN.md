# Production completion plan

A target production deployment is complete only when the following surfaces
have executable proof. The public alpha implements a subset; it is releasable as
a reference without satisfying these production gates.

Current implementation and environment-gate evidence is tracked in
`docs/IMPLEMENTATION_STATUS.md`.

1. Canonical decision engine and constraint-first PUCT.
2. Content-addressed scenario, benchmark, model, and experience manifests.
3. Authenticated receipt envelopes with key IDs, expiry, rotation, and replay controls.
4. Tenant-scoped authentication and authorization.
5. Durable SQLite WAL storage, migrations, append-only audit events, idempotency,
   budgets, leases, and crash-safe transactions.
6. Real allowlisted subprocess evidence with no shell, sanitized environment,
   exact executable resolution, timeout, output caps, and host fingerprint.
7. Hidden benchmark worker isolation; expected outputs never enter API responses
   or learning traces.
8. Immutable experience ingestion and transactional challenger learning.
9. Paired champion/challenger evaluation with hard-gate, quality, cost, and
   protected-regression checks.
10. Atomic promotion, canary state, rollback pointer, and complete audit history.
11. Health, readiness, Prometheus metrics, structured logs, backups, restore,
    key rotation, and incident runbooks.
12. Non-root container, read-only root filesystem, persistent data volume, and
    TLS reverse-proxy example.
13. Unit, integration, adversarial, restart, backup/restore, and rollback proof.
14. Independent production-readiness review with every P0/P1 closed.

Out of scope for a repository-local deliverable: creating the operator's cloud
account, provisioning a real secret manager/KMS, selecting real proprietary
hidden cases, and granting external write capabilities. The service fails closed
until operators supply those environment-owned resources.
