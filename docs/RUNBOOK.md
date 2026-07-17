# Production runbook

## Service contract

The process is `python -m agent_tree_rl.cli serve`. It listens on the configured
host and port, stores all durable state below `AGENT_TREE_RL_DATA_DIR`, reads API
token digests and receipt keys from private files, and exposes:

| Path | Meaning | Exposure |
|---|---|---|
| `/healthz` | Process/event loop is alive; does not promise dependencies work | Ingress and scheduler |
| `/readyz` | Store is writable and worker configuration is present; workers are not executed | Scheduler/backend only |
| `/metrics` | Prometheus text, with no task content or raw tenant labels | Monitoring network only |

An alive but unready instance receives no new work. Do not restart-loop an
instance merely because readiness is false; inspect the stated dependency first.

## Ownership and escalation

Assign named owners before launch:

- service on-call: availability, queues, database, restore;
- ML/controller owner: benchmark integrity, learning, canary, rollback;
- security on-call: credentials, signing keys, tenant boundary, audit export;
- platform owner: TLS ingress, workload identity, network policy, secret
  delivery, volumes, backup store, monitoring;
- tenant/product owner: approves high-impact actions and acceptable outcome risk.

The incident commander can freeze ingestion, learning, and promotion without
stopping read-only audit/export. Security can revoke a key or principal without
waiting for the model owner.

## Provisioning

1. Build in CI from a reviewed revision. Override `PYTHON_IMAGE` with an approved
   digest-pinned base. Generate SBOM, provenance, signature, and vulnerability
   report. Promote the application image by digest, never mutable tag.
2. Provision a dedicated workload identity, encrypted persistent volume,
   encrypted backup target in another failure domain, remote audit/log sink,
   metrics/alerts, TLS ingress, and default-deny network policies.
3. Provision API token digests, receipt and backup keyrings, a private hidden
   suite, and the benchmark-worker signing key through the secret manager. Give
   signing keys only to controlled workers. Treat the repository-local combined
   worker as lower assurance; do not use it for high-impact promotion.
4. Make secret files owned by the runtime identity and mode `0400` or `0600`.
   Never paste plaintext tokens or key bytes into shell history, Compose YAML,
   environment variables, tickets, or logs.
5. Set tenant quotas, reviewed evidence wrappers, allowed working roots, request
   size, workers, lease duration, hidden-attempt limit, and retention explicitly.
   Never expose a shell, interpreter, package installer, or network client.
6. Bootstrap into private staging, deliver all five externally generated private
   files through the platform secret mechanism, then run diagnostics as the
   final runtime identity:

   ```bash
   python -m agent_tree_rl.cli keyring check
   python -m agent_tree_rl.cli backup-keyring check
   python -m agent_tree_rl.cli doctor
   python -m agent_tree_rl.cli verify
   ```

7. Start one instance, wait for readiness, submit a non-side-effecting synthetic
   run for a test tenant, verify receipt/audit lineage, build a challenger, run a
   deliberately failing promotion, then exercise canary and rollback in staging.
8. Take and restore a staging backup before accepting production traffic.

`init` is for a new local evaluation directory only. It generates one-time local
tokens, keys, and the public sample benchmark, and refuses existing receipt/token
files. Never run it after production secrets are delivered. `verify` checks
controller/repository controls on disposable local state; it cannot attest cloud
IAM, ingress, backup, signing-worker independence, or the quality/secrecy of real
benchmarks.

The receipt keyring JSON has this versioned operational shape:

```json
{"active_key_id":"k-2026-07","keys":{"k-2026-07":"BASE64URL_32_OR_MORE_RANDOM_BYTES"}}
```

The API token file maps the lowercase SHA-256 digest of each randomly generated
bearer token to its principal; it never contains the plaintext token:

```json
{"64_HEX_SHA256_DIGEST":{"tenant_id":"TENANT_ID","roles":["agent"],"subject_id":"agent-service-v1"}}
```

Give operators/promoters/auditors separate credentials. Do not grant all roles
to one long-lived bootstrap token.

## Compose deployment

The example binds `127.0.0.1:8080` and expects local files under
`deploy/secrets/`. Those files are excluded from the image context and must be
delivered by a secret manager in production.

Compose's local file-secret implementation can ignore requested UID/GID/mode on
some engines. Prove inside the final container that UID 10001 can read the files
and that they are not group/world accessible. If the engine cannot provide that,
use the platform secret driver or a read-only root-owned `/run/secrets` policy
supported by the service; do not loosen the host source file permissions.

```bash
cd deploy
docker compose config --quiet
docker compose build --pull
docker compose up -d
docker compose ps
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
docker compose exec agent-tree-rl python -m agent_tree_rl.cli doctor
```

Keep `/readyz` and `/metrics` on the backend network. If the proxy is directly
internet-facing, replace the loopback binding only after configuring Caddy or a
platform ingress for TLS, client identity, request limits, rate limiting, and an
explicit trusted-proxy chain. The supplied Caddyfile intentionally uses HTTP
because it assumes TLS termination at the platform edge.

The application root filesystem is read-only. `/data` is durable and `/tmp` is a
bounded tmpfs. If a new feature requires another writable path, treat that as a
design review, not a permission workaround.

## systemd deployment

Install the application and virtual environment read-only under
`/opt/agent-tree-rl`, the unit under `/etc/systemd/system`, non-secret overrides
in `/etc/agent-tree-rl/service.env`, and every private credential named by
`LoadCredential`. Prefer `LoadCredentialEncrypted` backed by host
credentials when available.

```bash
systemd-analyze verify /etc/systemd/system/agent-tree-rl.service
systemctl daemon-reload
systemctl enable --now agent-tree-rl.service
systemctl status agent-tree-rl.service
curl --fail --silent --show-error http://127.0.0.1:8081/readyz
journalctl -u agent-tree-rl.service --since=-10m
```

The unit uses `DynamicUser`, a systemd-managed state directory, an empty
capability set, read-only system paths, syscall-adjacent hardening, and resource
limits. It denies IP traffic except localhost; a future remote provider or worker
must use a separately reviewed network boundary rather than weakening this unit
silently. Re-run `systemd-analyze security agent-tree-rl.service` after every
unit change. Some older systemd/kernel combinations may not support every
directive; remove one only with a documented compensating control.

## Normal operation

The reference exports uptime plus bounded request/outcome counters. Queue wait,
canary allocation, latency histograms, backup age, and delayed-outcome signals
below are target-state production observability and require external platform
instrumentation or future product work; they are not built-in `v0.1` metrics.

Watch four layers separately:

1. **Ingress:** request rate, auth failures, throttling, response codes, body
   rejection, upstream latency.
2. **Controller:** queue wait, active runs, abstentions, expansions, tool cost,
   lease expiry, idempotency conflicts, budget rejection.
3. **Evidence/learning:** verification failures, replay, expired/unknown keys,
   closed experiences, quarantines, benchmark coverage, protected regressions,
   promotion decisions, canary allocation.
4. **Store/host:** DB transaction latency/busy errors, WAL size/checkpoints, disk
   space/inodes, CPU, RSS, file descriptors, restarts, backup age and restore
   proof age.

Use request/run/evaluation IDs for correlation. Logs must not contain bearer
tokens, signing keys, full prompts, hidden answers, unbounded tool output, or raw
receipt payloads. Audit queries are access-controlled and tenant-scoped.

## Proposed production SLOs and alerts

These are target-state starting objectives for an operator to review and prove
in the real environment. They are not measured guarantees or current `v0.1`
capabilities:

| Objective | Target | Measurement |
|---|---:|---|
| Control-plane availability | 99.9% monthly | Valid non-overloaded API requests excluding planned maintenance |
| Admission latency | p95 < 250 ms, p99 < 1 s | Auth, validate, and reserve; excludes agent/tool runtime |
| Deadline fidelity | >= 99% | Accepted runs finish or produce explicit bounded timeout by declared deadline |
| Durable-state recovery | RPO <= 15 min; RTO <= 60 min | Quarterly restore drill using production-shaped encrypted backups |
| Promotion integrity | 100% | Every activation has passing report, authorization, audit lineage, rollback target |
| Tenant isolation | 100% | Zero cross-tenant disclosure or mutation; any event is a security incident |

External agent/tool latency gets a separate SLI by provider and workload class;
do not hide it inside controller availability. Exclude overload only when ingress
actually enforced the published quota. Track error-budget burn over 1-hour and
6-hour windows. Fast burn pages on-call; slow burn creates a release-blocking
ticket.

Page immediately for cross-tenant access, unauthorized/unsigned promotion,
receipt signing anomalies, key/replay failures above baseline, audit export
failure, active champion corruption, no ready instances, or projected disk
exhaustion under four hours. Alert for backup age > 20 minutes, last restore drill
> 90 days, WAL growth, lease-expiry spikes, protected benchmark regression, and
canary outcome degradation.

## Graceful restart and upgrade

Steps involving parallel versions and traffic percentages require an external
rollout layer; the single-process reference does not implement cohort routing.

1. Freeze promotions. Confirm no key rotation or restore is active.
2. Record active champion hash, schema version, queue depth, leases, backup ID,
   and image digest.
3. Take a verified pre-change backup.
4. Start the new version with zero canary traffic. Require `/readyz`, `doctor`,
   schema compatibility, and a synthetic decision.
5. Route a stable 1% canary cohort. Compare errors, queue time, cost, abstention,
   evidence validity, and delayed outcomes to the old version.
6. Expand 1% -> 5% -> 25% -> 50% -> 100%, with a full observation window at
   each step. Never advance on missing telemetry.
7. Stop assigning work to the old instance, then send SIGTERM. The process
   makes `/readyz` fail, rejects new work, closes its listener, and waits up to
   `AGENT_TREE_RL_SHUTDOWN_GRACE_SECONDS` (30 seconds by default) for admitted
   work. Health/readiness/metrics use separate bounded capacity and do not keep
   the work drain open. At that deadline, the service TERM/KILLs and reaps every
   exactly registered evidence or hidden-benchmark process group within
   `AGENT_TREE_RL_SHUTDOWN_CANCEL_SECONDS` (5 seconds by default), then lets the
   request transaction fail closed before releasing the store/runtime lock.
   Set the supervisor/container stop deadline longer than both application
   phases combined (the supplied examples use 40 seconds for 30+5 seconds).

The registry owns process groups, not a kernel containment boundary. A custom
executable that deliberately forks and calls `setsid()` can leave its registered
group. The shipped evidence probe and fixed internal candidate do not fork.
Before allowing any custom production worker, run each job in a disposable
container/cgroup (or equivalent supervisor-owned sandbox), prohibit daemonizing,
and test that the job boundary is empty before service lock release.
8. Keep the previous image and compatible database backup through the rollback
   window.

Only one service process may own a data directory. Startup takes an exclusive
POSIX lock before opening the database; a parallel service fails closed. After
an ungraceful exit, service startup atomically marks inherited `IN_PROGRESS`
idempotency records as `FAILED` with `retry_safe=false`, releases only
`RESERVED` (never `CONSUMED`) budget capacity, and fences inherited leases. The
old key becomes a non-expiring tombstone because an external tool may already
have acted; investigate external effects before submitting a new key. A budget-row
versus reservation-ledger mismatch aborts startup recovery without mutation.
Backup, restore, doctor, and ordinary store opens never run this reconciliation.

Database migrations must be backward-compatible through the canary window.
Destructive migration follows expand/migrate/contract in separate releases.
Never run two incompatible binaries against one SQLite file.

## Controller/model canary and rollback

A production canary router must use a stable hash of tenant and run identity so
one run never switches policy mid-tree. The reference does not provide that
router. Start with shadow evaluation when actions are expensive or irreversible.
Canary gates include hard failures and protected strata before aggregate reward.

Rollback immediately on:

- any safety hard-gate failure or unauthorized side effect;
- statistically credible protected-stratum regression;
- cross-tenant, receipt, audit, or budget invariant failure;
- material cost/latency increase outside the approved bound;
- loss of evaluation telemetry or unexplained outcome drift.

Rollback is an authorized compare-and-swap to the recorded prior champion, not a
retraining job. Freeze learning/promotion, record incident and affected run IDs,
restore the pointer, confirm new runs use the old hash, and let already committed
side effects finish only according to their external safety contract. Do not
delete the failed challenger; quarantine it and preserve lineage for analysis.

## Backups

The application emits an authenticated `.atrlb` ZIP_STORED bundle containing a
consistent database snapshot, every referenced content-addressed policy object,
and a canonical HMAC manifest. It excludes API, receipt, benchmark, and backup
secrets plus the hidden suite. Encrypt it in transit/at rest, store it in a
different failure domain, and apply immutability and retention.

Use the application backup command because it uses SQLite's consistent backup
mechanism rather than copying a live database:

```bash
python -m agent_tree_rl.cli doctor
python -m agent_tree_rl.cli backup --output /secure-staging/agent-tree-rl-backup.atrlb
sha256sum /secure-staging/agent-tree-rl-backup.atrlb
```

The platform then encrypts/uploads the artifact and removes staging according to
policy. Never log or paste its contents. Run at least every 15 minutes for the
stated RPO; keep daily/weekly versions according to legal and tenant retention.
Alert on command failure, checksum/upload failure, or stale backup. A successful
upload is not proof until restore succeeds.

## Restore

Restore is a controlled incident/change with two-person approval because it can
change the champion and replay ledger.

1. Block ingress, evidence ingestion, learning, promotion, and signing. Preserve
   read-only incident telemetry.
2. Stop the application. Record image digest, active champion, last audit event,
   and affected backup ID. Preserve the failed volume read-only.
3. Fetch into a clean, isolated host; verify backup signature, checksum,
   encryption metadata, expected source, schema, and service compatibility.
4. Restore into an empty data directory, never over live state:

   ```bash
   python -m agent_tree_rl.cli restore --input /secure-staging/agent-tree-rl-backup.atrlb
   python -m agent_tree_rl.cli doctor
   python -m agent_tree_rl.cli keyring check
   python -m agent_tree_rl.cli verify
   ```

   If the host crashes between object-tree and database activation, rerun the
   exact same restore command with the same bundle and backup keyring. The
   authenticated recovery marker validates the signed bundle, staged database,
   and every policy hash before completing the second rename.

5. Verify database integrity, monotonic audit-event sequence, per-payload hashes,
   object hashes, tenant counts, active and rollback model hashes, budget
   invariants, nonces, pending leases, and latest receipt key IDs. If a remote
   hash-linked audit export exists, verify its continuity separately. Expire
   orphaned leases safely; do not discard replay claims.
6. Start isolated with workers/signing disabled. Run tenant-isolation probes and
   read-only synthetic cases.
7. Reconcile post-backup external side effects and receipt nonces from the remote
   audit/tool systems. Quarantine ambiguous experiences; never replay a
   side-effecting action merely because the database forgot it.
8. Reopen to an internal canary, then production. Create a fresh backup and
   incident/change report.

Exercise restore quarterly and after schema, encryption, backup format, or major
storage changes. Measure RPO/RTO from evidence, not estimates.

## Receipt-key rotation

Normal rotation uses overlap:

1. Freeze promotions and snapshot key-ID usage/receipt maximum TTL.
2. Create a new key in KMS/secret manager. Register its unique key ID, purpose,
   issuer, tenant scope, environment, and validity policy.
3. Deliver a keyring containing old verification key plus new verification key.
   Run `keyring rotate`, `keyring check`, and reload/restart canaries:

   ```bash
   python -m agent_tree_rl.cli keyring rotate
   python -m agent_tree_rl.cli keyring check
   ```

   Run the mutating command against an access-controlled writable staging copy,
   then publish a new immutable secret-manager version atomically. Production
   `/run/secrets` and systemd credential mounts remain read-only.
4. Switch controlled workers to sign with the new key. Confirm new receipts use
   it and old receipts still verify.
5. Wait at least maximum receipt TTL plus clock-skew and queue/retry windows.
6. Remove the old verification key, restart gradually, and prove an old receipt
   is rejected after its permitted window.
7. Record key IDs, times, approvers, affected issuers, and audit references.

Do not reuse key IDs or key material across development, staging, production,
tenant trust classes, or unrelated purposes.

Rotate the separate backup keyring with the same overlap discipline. Retain old
verification keys for every unexpired retained bundle, or re-sign/re-encrypt
those bundles under an approved migration:

```bash
python -m agent_tree_rl.cli backup-keyring rotate
python -m agent_tree_rl.cli backup-keyring check
```

For suspected compromise: freeze ingestion/learning/promotion, disable the key
at issuers and verifiers, preserve audit, identify all receipts/experiences/models
by key ID and validity window, quarantine derived challengers, roll back if an
affected model was activated, rotate API/worker credentials, and notify security
and affected tenants. Restoring from backup does not make compromised receipts
trustworthy.

API bearer-token rotation similarly adds a new digest/principal, deploys clients,
observes old-token silence, then removes the old digest. Never store plaintext
tokens in the service token file.

## Incident response

### Common first actions

1. Declare severity and incident commander; start an access-controlled timeline.
2. Preserve evidence. Record UTC time, image/config/model/key IDs, request/run
   IDs, metrics, audit range, and recent changes. Export remote logs; do not copy
   secrets or full tenant payloads into chat.
3. Contain at the narrowest safe boundary: tenant/principal, receipt issuer/key,
   worker/tool, challenger/canary, or ingress. Freeze all promotion on uncertainty.
4. Keep read-only audit access when safe. Prefer abstention and queue rejection
   over executing with degraded safety controls.
5. Eradicate, recover through the canary path, notify owners/tenants as required,
   and write follow-ups with owners and deadlines.

### No ready instances

Check one fact per layer: proxy upstream, process health, readiness response/log,
secret presence/permissions, disk space, database integrity/migration, keyring,
and worker dependency. After two identical failed recovery attempts, classify as
application, bootstrap/config, transport/environment, or platform/infra and
pivot. Do not restart repeatedly; it can erase the first-failure signal and
amplify lease churn.

### Database busy, corrupt, or disk full

Stop new admissions and promotions. For disk pressure, preserve DB/WAL/audit and
remove only documented disposable caches/logs outside `/data`; do not delete WAL
or SHM files. Capture integrity diagnostics and volume snapshot. If corruption is
confirmed, stop writers and use the restore procedure. Reconcile externally
committed actions before reopening.

### Cross-tenant exposure

Treat any suspected exposure as highest severity. Block affected routes or all
traffic, preserve audit/query logs, revoke implicated principals, freeze exports,
promotion, and deletion, and engage security/privacy/legal response. Determine
read versus write scope, tenants, fields, time window, cache/export/backup
propagation, and derived model lineage. Physical tenant separation is the likely
corrective control for incompatible trust domains.

### Bad promotion or unsafe action

Freeze promotion and the side-effecting tool, restore the prior champion pointer,
quarantine derived experiences, and identify actions already committed outside
the service. External compensation follows the owning tool's runbook; never
assume model rollback reverses world state. Preserve the exact evaluation report
and determine whether the failure was benchmark coverage, evidence authenticity,
policy, implementation, or environment drift.

### Receipt anomaly

On replay/invalid-signature spikes, isolate by key ID, issuer, tenant, purpose,
and source. Rate-limit ingestion, confirm clock health, and distinguish client
retry from forgery. Unknown-key errors after planned rotation are operational;
valid signatures from an unauthorized issuer/purpose are a policy breach.

## Decommissioning

Freeze new runs and promotion, drain or explicitly cancel bounded work, export
tenant data and audit according to contract, revoke all principals and signing
keys, take the final verified backup, remove ingress/DNS, destroy runtime volumes
only after retention approval, schedule backup expiry, and retain an auditable
decommission record. Confirm no orphan worker credentials, webhooks, secret
versions, images, or monitoring routes remain.
