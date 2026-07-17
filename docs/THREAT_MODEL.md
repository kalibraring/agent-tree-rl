# Threat model

## Security objectives

1. Only authenticated principals can read or mutate tenant data.
2. No tenant can observe, spend, train on, promote, or replay another tenant's
   work.
3. Untrusted agents cannot fabricate evidence that changes durable learning.
4. A compromised worker cannot silently broaden its tools or promote a model.
5. Promotion and rollback remain attributable, atomic, and recoverable.
6. Secrets, benchmark answers, task content, and model data do not leak through
   logs, metrics, errors, images, backups, or artifacts.
7. Resource exhaustion fails boundedly and preserves audit/state integrity.

## Assets and trust boundaries

Critical assets are API tokens, receipt signing keys, hidden benchmark cases,
tenant task/evidence data, budgets, audit events, replay nonces, worker
credentials, and champion/challenger pointers.

Untrusted inputs include all agent output, request bodies, tool stdout/stderr,
repository content, URLs, filenames, model manifests, benchmark submissions, and
receipt envelopes before verification. Reverse proxy, service, database,
evidence worker, benchmark worker, secret manager, backup system, and promoter
are separate trust boundaries.

## Threats and required controls

| Threat | Example | Required controls | Residual risk / acceptance gate |
|---|---|---|---|
| Forged receipt | Agent signs its own claimed success | Signing key only in controlled verifier; canonical envelope; purpose/tenant/content binding; expiry; nonce; constant-time verification | HMAC proves key possession, not truthful execution. Require workload identity and attested artifacts for high-impact proof. |
| Replay | Reuse one passing receipt for many moves | Atomic `(tenant, purpose, nonce)` claim; content hash; expiry; idempotency | Restore can resurrect old nonce state. Restore procedure must preserve and reconcile replay ledger. |
| Key compromise | Worker key is exfiltrated | Per-environment/purpose keys; secret manager; short receipt TTL; overlap rotation; emergency revoke; immutable audit | Receipts signed before detection may be suspect. Quarantine affected experiences/models by key ID. |
| Cross-tenant access | Guess another run/model ID | Derive tenant from credential; tenant predicate in every query and cache key; negative integration tests | In-process compromise bypasses logical isolation; isolate high-assurance tenants physically. |
| Role escalation | Agent calls promote endpoint | Deny by default RBAC; promoter role; separation of duties; step-up auth upstream; audit | Token theft carries assigned roles until revoked. Use short-lived workload identity where possible. |
| Prompt/tool injection | Repository text asks verifier to leak keys | Treat content as data; fixed allowlist; no shell; sanitized env; fixed cwd roots; output caps; sandbox/network policy | A permitted executable may itself be exploitable. Pin and patch worker images. |
| Worker daemon/process escape | Custom executable forks and leaves its registered process group | Shipped wrappers do not fork; TERM/KILL/reap registered groups; require per-job container/cgroup and no-daemon policy for custom workers | Process-group tracking alone cannot contain deliberate `setsid()` escape. Kernel/supervisor isolation is an environment-owned production gate. |
| Path traversal/symlink race | Evidence command escapes workspace | Canonical allowed roots; dirfd/safe-open where needed; sandbox mount namespace; immutable checkout | Host-local runner alone is insufficient for hostile repos. Use disposable sandbox. |
| Command injection | Candidate controls command text | Structured argv; exact executable allowlist; `shell=False`; no inherited environment | Broad interpreters (`python`, `bash`) collapse the boundary; do not allowlist them for untrusted input. |
| SSRF/egress abuse | Tool fetches metadata endpoint | Default-deny worker egress; destination allowlist; block link-local/private ranges; platform identity off by default | DNS rebinding and allowed endpoint compromise require proxy-level enforcement and logging. |
| Hidden-set leakage | Expected answers appear in trace | Separate worker/store/identity; opaque case IDs; no expected values in API/logs; rotate contaminated suite | Repeated adaptive evaluation can infer the set. Rate-limit, use holdbacks, refresh cases. |
| Benchmark gaming | Aggregate gain hides safety loss | Hard gates before scalar score; protected strata; paired cases; uncertainty; minimum sample | Benchmarks remain proxies. Canary and delayed real-outcome monitoring are mandatory. |
| Data poisoning | Low-quality receipts train policy | Trusted issuer policy; quarantine; dedupe; provenance; influence caps; anomaly detection | Trusted workers can still be wrong. Support revocation and deterministic rebuild excluding bad lineage. |
| Sybil/collusion | Many subagents echo same claim | Independence based on issuer/evidence lineage, not agent count; correlated vote collapse | Common model/provider failures remain correlated. Keep heterogeneous proof surfaces. |
| Resource exhaustion | Huge tree or slow tools | Request/node/depth/time/output/cost limits; tenant quotas; queue bounds; leases; cancellation; rate limits | External tools can hang or bill after cancellation; use provider-side limits and reconciliation. |
| Race/double spend | Concurrent runs consume same budget | Transactional reservation; idempotency; compare-and-swap; durable leases | SQLite write contention limits scale; do not add writers without shared transactional design. |
| Promotion race | Two challengers become champion | Immutable models; one atomic active-pointer CAS; authorized promoter; audit | Bad but valid promotion needs canary/rollback and outcome alerts. |
| Rollback attack | Attacker selects vulnerable old model | Rollback allowlist; revoked-model state; authorization; audit; security floor independent of model | Emergency rollback may trade quality for safety; document approval. |
| Audit tampering | Delete adverse outcome | Current reference: append-only DB triggers and per-payload hashes. Production: previous-hash linkage, remote immutable export, restricted DB access, and backup verification. | Same-host root can alter local DB and logs. Remote WORM sink is required for strong nonrepudiation. |
| Secret leakage | Token in logs or image | File secrets; digest-only API token store; redaction; `.dockerignore`; image/SBOM scans | Request bodies/tool output may contain secrets. Apply content filters and restricted log access. |
| Malicious backup/restore | Restore altered champion pointer | Encrypt/sign backup manifest; checksums; isolated credentials; restore drill; post-restore invariants | Backup operator is privileged. Separate duties and log restores. |
| Supply-chain compromise | Poisoned base image/package | Digest-pinned base image; hash-locked CI build dependencies; SBOM/provenance/signature; scan; reproducible build | Maintainers must deliberately refresh the pinned digest and hashes, review upstream changes, and prove the rebuilt image. |
| Proxy spoofing | Client sends fake forwarding headers | App never consumes forwarding headers; ingress overwrites them and supplies transport policy | Adding forwarding-header trust without an explicit proxy allowlist is prohibited. |
| Availability failure | DB/disk/process outage | Health vs readiness; disk alerts; bounded restart; graceful stop; backup/restore; capacity headroom | Single-node reference has an outage during host failure. Meet stricter SLOs with tested HA datastore design. |

## Receipt authenticity decision

A cryptographically valid receipt is necessary but not sufficient evidence. The
issuer policy is as important as the signature. Production acceptance requires
a registry that maps each key ID to issuer identity, permitted purpose, tenant or
tenant class, environment, validity interval, and revocation state. Verification
must reject a valid signature used outside that policy.

For proof that a command ran, the controlled worker—not the candidate—constructs
the receipt from captured exit status, bounded output/artifact digests, exact
argv, working-tree/revision hash, toolchain image digest, timestamps, and host or
sandbox identity. The signing step happens only after the worker independently
checks those fields. Where platform attestation is unavailable, label evidence
`unattested` and prohibit it from high-impact promotion.

## Tenant isolation decision

The reference service offers logical tenant isolation in one process/database.
It is appropriate only when tenants share an administrative trust domain and
cross-tenant tests pass. Regulated, mutually hostile, or cryptographically
isolated tenants get separate deployments, stores, worker pools, keys, backup
paths, and observability sinks.

## Reference worker trust-domain decision

The bundled controller, benchmark client, and local worker share one
administrative trust domain. Worker CLI paths come only from privileged startup
configuration or controller-derived content-addressed artifacts; they are not
accepted from HTTP request fields. The implementation still validates exact
executables, working-root containment, private regular files, byte caps,
symlinks, inode stability, and artifact digests.

That local arrangement does **not** prove independence from a compromised
controller. A production independence claim requires a separately governed
worker whose immutable configuration owns the executable allowlist, working
roots, benchmark path, signing-key path, and candidate-ID-to-artifact mapping.
Its job protocol should accept only a candidate ID/digest, nonce, and bounded
input—not controller-selected filesystem paths. Candidate execution must run in
a separate sandbox without benchmark or signing-key mounts, and only the trusted
worker may sign the validated aggregate.

## Abuse and privacy controls

- Set per-principal and per-tenant request, concurrency, tool, token, storage,
  and spend limits; enforce at ingress and transactionally in the service.
- Reject secrets and sensitive data from model features unless explicitly
  allowed. Redact logs at source and set short, documented retention.
- Local `init` writes one-time bootstrap tokens to an exclusive mode-`0600`
  file instead of stdout. Import it into a secret manager and securely delete it
  immediately; production deployments must provision workload credentials
  externally.
- Never label metrics with prompts, task IDs, raw tenant IDs, paths, model
  content hashes, or unbounded error strings.
- Provide tenant export/deletion workflows that preserve only legally required,
  access-controlled audit tombstones.
- Alert on repeated auth failures, receipt failures/replays, cross-tenant probes,
  unusual signing rates, benchmark access, promotion attempts, and rollback.

## Security verification before launch

- Threat-model review includes service, worker, ingress, secrets, backup, and
  actual cloud/IAM/network configuration.
- Automated negative tests cover every route/role and cross-tenant object type.
- Fuzz canonical JSON, receipt parsing, size/depth limits, and state transitions.
- Exercise replay under concurrency, key overlap/revocation, restore, and clock
  skew.
- Escape-test the real worker sandbox with hostile repository files, symlinks,
  command arguments, output floods, forks, timeouts, and blocked network targets.
- Run image, dependency, secret, IaC, and SBOM/provenance checks.
- Perform a tabletop for signing-key compromise and a bad-model promotion.

## Accepted limitations of the reference deployment

The repository cannot provision external KMS, workload identity, WORM audit
storage, attested sandbox workers, TLS ingress, hidden proprietary benchmarks,
or cross-region backup infrastructure. Production ownership must supply and test
these. Until then, the service may be production-shaped but must not be declared
safe for privileged or irreversible agent actions.
