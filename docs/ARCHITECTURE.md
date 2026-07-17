# Production-oriented reference architecture

## Purpose and invariant

Agent Tree RL is a governed decision controller. It stores chess-like decision
positions, searches legal agent/subagent moves, evaluates independently observed
outcomes, and promotes a challenger policy only after protected benchmarks pass.
It must never treat an agent's confidence, prose, predicted score, or
self-authored receipt as proof of real-world success.

The safety invariant is:

> An untrusted proposal may influence search, but only authenticated,
> independently generated evidence may influence durable learning or promotion.

This service improves the controller's move-selection policy. It does not mutate
its own executable, grant itself tools, bypass approvals, or train a foundation
model in place.

## Runtime topology

```text
authenticated client / agent
             |
             | TLS, request identity, tenant context, idempotency key
             v
   platform ingress / Caddy
       | public: API, /healthz
       | private: /readyz, /metrics
       v
  Agent Tree RL service  <---- read-only API-token and receipt-key files
       |       |
       |       +---- allowlisted evidence runner / hidden benchmark worker
       |             (separate identity and sandbox in a full deployment)
       v
  SQLite WAL + manifests + append-only audit stream under /data
       |
       +---- encrypted, versioned backup store in another failure domain
```

The supplied Compose deployment runs one application process and one Caddy
process. It binds Caddy to loopback by default so a production TLS ingress can
apply identity, rate limits, and request logging. The systemd unit binds the
application to loopback. Never expose port 8081 directly.

## Components

### API and controller

- Parses bounded JSON and rejects unknown/invalid state transitions.
- Authenticates bearer tokens from a private file containing only SHA-256 token
  digests and tenant/role bindings.
- Authorizes every action by role (`agent`, `operator`, `promoter`, `auditor`).
- derives tenant identity from the authenticated principal, never request JSON.
- Applies tenant-scoped quotas, leases, idempotency, and concurrency limits.
- Runs constraint-first PUCT over immutable, content-addressed moves.
- Returns abstention when evidence, budget, or safety gates are insufficient.

### Durable store

SQLite in WAL mode is the reference single-node store. Transactions atomically
couple state transitions, nonce claims, budget accounting, model pointers, and
append-only audit events. The database, WAL, SHM, and policy objects belong on
the same persistent filesystem. Use the authenticated application bundle; it
uses SQLite's live backup API and verifies every referenced immutable object.

One writer instance is the supported reference topology. Horizontal API replicas
require replacing local leases, replay claims, budgets, and atomic promotion
pointers with a transactional shared store. A shared network filesystem is not a
safe shortcut.

### Evidence and benchmark workers

Production workers use a distinct workload identity and a strict command/tool
allowlist. They receive bounded inputs, a sanitized environment, fixed working
roots, deadlines, output limits, and no shell interpolation. Hidden expected
answers stay outside API responses, traces, and learning data.

The bundled single-process runner is suitable only for low-risk, host-local
commands. Code execution, arbitrary repository work, browser sessions, or
privileged tools require an external sandbox with per-job credentials and
network policy.

### Receipt trust

Receipt envelopes bind canonical content, purpose, tenant, key ID, issuance,
expiry, and nonce under an HMAC. Verification establishes that a holder of the
key signed exactly those bytes and that the receipt is timely and non-replayed.

It does **not** establish that:

- the signer was independent of the candidate;
- the named command or tool actually ran;
- output came from the claimed host, repository, or revision;
- the benchmark was hidden or uncompromised;
- the observation describes the external world truthfully.

Therefore only a controlled verifier/worker may hold signing keys. Agent workers
get verification access or unsigned submission rights, never signing keys.
High-impact evidence should additionally carry platform workload identity,
artifact hashes, immutable logs, source revision, environment fingerprint, and
an external attestation or transparency-log reference. A receipt created from
agent-supplied claims is authenticated fiction and must not unlock promotion.

### Champion/challenger registry

Learning creates an immutable challenger. Evaluation compares champion and
challenger on the same case IDs and environment version, using paired results.
Hard safety gates, protected-stratum regressions, cost/latency limits, minimum
sample size, and uncertainty bounds precede aggregate score. Promotion is one
audited compare-and-swap of the active pointer. The prior champion remains
addressable for instant rollback.

## Request and learning flows

### Decision run

1. Ingress authenticates the transport; the service authenticates the API token.
2. The service derives tenant and role, validates size/schema, and reserves a
   tenant budget under an idempotency key.
3. Candidate agents propose legal moves. Proposals remain untrusted.
4. Search selects expansion/evaluation work within depth, cost, and time limits.
5. A controlled verifier runs the narrow proof and emits evidence plus a signed
   receipt bound to the move and environment hashes.
6. The service verifies purpose, tenant, signature, expiry, and nonce, then
   commits outcome, cost, and audit event atomically.
7. The controller commits the best legal action or abstains. Side-effecting
   actions still pass the external approval/tool authorization boundary.

### Learn, evaluate, promote

1. Close eligible experiences only after independent terminal evidence arrives.
2. Freeze a content-addressed training manifest; exclude quarantined, expired,
   duplicate, and holdout cases.
3. Build a challenger transactionally. Never edit the champion in place.
4. Evaluate a pinned challenger, champion, suite, code revision, and environment.
5. Require minimum coverage, hard gates, protected strata, paired statistics,
   cost/latency bounds, and no benchmark-integrity alarms.
6. Require an authorized promoter distinct from the candidate-producing actor
   for high-impact tenants.
7. In a production rollout layer, canary by stable tenant/run hashing and
   monitor leading and outcome metrics. The reference service does not yet
   implement canary routing.
8. Expand gradually or atomically restore the prior champion pointer.

## Tenant isolation

Tenant isolation is a row-level and operational boundary, not a naming
convention.

- Tenant comes exclusively from authenticated credentials.
- Every mutable and immutable database record, nonce, budget, lease, audit
  query, receipt, model overlay, and benchmark attempt includes tenant scope.
- Receipt keys, benchmark keys, API-token files, database files, artifact roots,
  and backup/restore operations are deployment-scoped in `v0.1`; a backup is a
  whole-store operation, not a tenant export.
- Authorization tests must exercise cross-tenant object IDs and idempotency keys.
- Metrics avoid raw tenant IDs and task text; use bounded labels or a separate
  access-controlled analytics pipeline.
- Shared/global models may consume tenant data only under an explicit policy,
  redaction/retention contract, and contribution ledger. The default is a
  tenant-local overlay.
- High-assurance tenants require separate service/database/keys, because a
  process compromise defeats logical row isolation.

## Availability, performance, and scaling

The reference target is one service writer per SQLite data directory, enforced
by an exclusive POSIX runtime lock. Normal work and operational probes have
separate bounded concurrency. SIGTERM makes readiness fail and closes work
admission before a bounded drain. On restart, only the lock-owning service
reconciles inherited in-progress idempotency records, reserved budget, and
leases; generic store opens do not. Completed effects and consumed budget share
one transaction, while ambiguous external effects fail closed instead of being
automatically retried. A durable queue is future product work and must recover
abandoned work under the same accounting/fencing invariants. Apply backpressure
before CPU, database, or external-tool saturation.

Suggested starting limits:

- request body: 1 MiB at the app, 10 MiB absolute proxy ceiling;
- application workers: 8, tuned from measured queue time and DB contention;
- one decision's search budget: explicit nodes, wall time, tool calls, and cost;
- per-tenant concurrent runs and daily budget: configured independently;
- SQLite database: monitor WAL growth, checkpoint latency, disk space, and busy
  errors; migrate to a transactional server database before multi-writer scale.

## Deployment and secret boundaries

- Root filesystem is read-only; `/data` is the only durable writable mount and
  `/tmp` is a bounded noexec tmpfs.
- The application runs as UID/GID 10001 in containers or a systemd DynamicUser.
- All Linux capabilities are dropped and `no-new-privileges` is set.
- API token digests and receipt keys enter through read-only files. They are not
  image layers, Compose environment values, logs, or command arguments.
- A real deployment sources those files from KMS/secret-manager delivery and
  pins images by digest. The example local secret files are a wiring mechanism,
  not a secret-management system.
- TLS, workload identity, network policy, WAF/rate limiting, log sink, alerting,
  backup storage, and attested worker infrastructure are environment-owned.

## Safe extension points

Add an agent, evaluator, tool, or scoring metric only through a versioned
manifest with an owner, input/output schema, timeout, cost ceiling, permission
set, benchmark coverage, and rollback plan. New metrics first run in shadow mode.
No plugin may write the model registry, database, key files, or audit history
directly.

## Explicit non-goals

- autonomous code or policy deployment without a controlled release;
- arbitrary shell or network access for candidate agents;
- accepting agent-created receipts as independent evidence;
- live online learning directly into the champion;
- claiming global optimality from a bounded, partially observed search tree;
- using the local Compose topology as proof of cloud production readiness.
