# Production completion checklist

Production is an evidence state, not a repository label. Every required item
below needs an owner, environment, dated proof link, expiry/retest date, and
explicit acceptance. Repository tests cannot prove cloud IAM, worker
independence, backup recovery, or real benchmark quality.

Use three statuses: **PASS** (fresh evidence), **BLOCKED** (named dependency and
owner), or **FAIL** (observed defect). Blank means not assessed. Any P0/P1,
security invariant, restore, tenant isolation, receipt trust, or promotion gate
that is not PASS blocks production.

## 1. Scope and risk

- [ ] Named product, service, ML/controller, security, platform, privacy, and
      on-call owners accept their responsibilities.
- [ ] Supported workloads, tenants, data classes, regions, action impact, tool
      permissions, cost ceilings, and prohibited uses are written down.
- [ ] The controller improves a bounded policy; it cannot rewrite/deploy itself,
      broaden tools, bypass approval, or silently train the champion online.
- [ ] External side effects have independent authorization, idempotency,
      reconciliation, and compensation contracts.
- [ ] Safety policy defines mandatory abstention and human approval cases.
- [ ] Threat model is reviewed against the actual platform, not only the local
      topology; all high risks have controls and owners.

## 2. Decision semantics

- [ ] Position, legal move, transition, terminal outcome, uncertainty, cost, and
      abstention schemas are versioned and canonical.
- [ ] State and move hashes include all semantics that affect legality, score,
      evidence, cost, permissions, and environment.
- [ ] Constraint/hard-gate evaluation precedes scalar reward.
- [ ] Search is bounded by nodes, depth, time, tool calls, output, and spend.
- [ ] Cycles/transpositions, stale evidence, conflicts, partial outcomes,
      cancellations, timeouts, duplicate proposals, and no-legal-move states have
      deterministic behavior.
- [ ] Learned priors cannot suppress novelty/abstention or override legality.
- [ ] Correlated agents/evidence are not counted as independent votes.
- [ ] Deterministic replay pins code, config, suite, model, tool/environment, and
      random seed where applicable.

## 3. Authentication, authorization, and tenants

- [ ] Authentication is mandatory outside isolated local development and fails
      closed when token files are absent, malformed, or too permissive.
- [ ] Token file contains SHA-256 digests only, with explicit tenant and minimal
      roles; plaintext bearer tokens live only in the secret manager/client.
- [ ] Tenant identity always comes from the authenticated principal, never body,
      header, path, receipt payload, or model output.
- [ ] Every route has allow/deny tests for `agent`, `operator`, `promoter`, and
      `auditor`; promotion uses separation of duties where impact requires it.
- [ ] Every table/query/cache/nonce/idempotency key/budget/lease/audit/export,
      artifact, receipt, benchmark, and model overlay is tenant-scoped.
- [ ] Automated hostile tests guess cross-tenant IDs for every object and prove
      no existence leak, read, mutation, spend, replay, or training influence.
- [ ] Tenant-scoped encryption, worker identity, paths, logs, deletion/export,
      retention, and backup restore are proven.
- [ ] Mutually hostile or regulated tenants use separate deployment/store/keys/
      workers/backups, or security explicitly accepts shared-process risk.

## 4. Receipt and evidence authenticity

- [ ] Canonical receipts bind version, algorithm, key ID, purpose, tenant,
      content/artifact/environment hashes, issuance, expiry, and unique nonce.
- [ ] Verification checks issuer policy, purpose, tenant, key state, signature,
      clock skew, expiry, and atomic replay claim before durable use.
- [ ] Candidates and general agent workers never receive signing keys.
- [ ] Controlled verifier constructs receipts from captured execution; it never
      signs agent-authored assertions.
- [ ] Exact argv/executable, sanitized environment, cwd/revision, exit status,
      bounded output/artifact hashes, timestamps, tool image, and worker identity
      are included in evidence lineage.
- [ ] High-impact evidence carries platform attestation/transparency evidence;
      unattested receipts are labeled and barred from high-impact promotion.
- [ ] Per-environment/purpose key isolation, overlap rotation, emergency revoke,
      key-ID lineage quarantine, and clock failure are tested.
- [ ] Concurrent replay, malformed canonical JSON, duplicate keys, large/deep
      payloads, unknown/revoked keys, and timing boundary cases are tested.
- [ ] Everyone understands that HMAC authenticity proves key possession and byte
      integrity—not truth, independence, or execution. Issuer controls close that
      gap.

## 5. Worker and tool isolation

- [ ] Tool execution uses structured argv, `shell=False`, exact executable and
      cwd allowlists, sanitized environment, deadlines, output/process/memory/
      file/network limits, and cancellation.
- [ ] Broad interpreters, package installers, shells, host sockets, cloud
      metadata, and credential directories are absent from untrusted jobs.
- [ ] Hostile repository tests cover traversal, symlinks, injection, forks,
      output flood, timeout, signal behavior, and egress/SSRF.
- [ ] Production agent/evidence/benchmark jobs run in disposable sandboxes with
      per-job minimal workload identity and default-deny egress.
- [ ] Worker image/tool versions are digest-pinned, patched, scanned, attested,
      and included in receipts.
- [ ] Timeout/cancel reconciles provider billing and late side effects.

## 6. Persistence and consistency

- [ ] Migrations are versioned, transactional/idempotent, upgrade-tested, and
      backward compatible for the canary window.
- [ ] SQLite WAL, foreign keys, busy timeout, synchronous durability policy,
      integrity checks, checkpoints, and disk alerts are configured and measured.
- [ ] One-writer limitation is enforced. Multi-replica plans use a transactional
      shared store; no shared-filesystem SQLite.
- [ ] State change, budget reservation, idempotency result, nonce claim, lease,
      audit event, and promotion pointer use correct atomic transaction boundaries.
- [ ] Crash/restart tests cover every commit boundary, orphan lease, duplicate
      request, partial artifact, and interrupted learn/evaluate/promote.
- [ ] Audit is append-only/hash-linked and exported to restricted remote
      immutable storage; same-host root tampering is in the threat model.
- [ ] Retention, export, erasure, legal hold, and derived-model lineage policies
      are implemented for each data class.

## 7. Learning and benchmark governance

- [ ] Experiences are immutable, deduplicated, provenance-complete, closed only
      by independent outcomes, and quarantinable/revocable by lineage.
- [ ] Training manifests are content-addressed and pin code/config/data filters;
      rebuild excluding a bad key/worker/case is deterministic.
- [ ] Hidden cases/answers use separate store, identity, worker, logs, and API;
      expected values never enter traces, errors, or learning input.
- [ ] Suite contamination, repeated adaptive probing, drift, and case retirement
      have detection and response processes.
- [ ] Champion/challenger comparison is paired on identical case/environment IDs
      with minimum sample, uncertainty, hard gates, protected strata, quality,
      latency, and cost thresholds.
- [ ] Champion is immutable; activation is an authorized atomic compare-and-swap
      with audit and a non-revoked rollback target.
- [ ] Shadow, 1/5/25/50/100% canary, stable cohort allocation, observation windows,
      automatic/manual halt, and instant pointer rollback are proven.
- [ ] Delayed real outcomes feed monitoring and governed future training, never a
      direct unreviewed champion update.

## 8. API and abuse resistance

- [ ] Request parsing has byte, nesting, list/map, string, number, header, and
      deadline limits; unknown fields and non-finite numbers fail closed.
- [ ] Per-principal/tenant ingress rate limits and durable concurrent/tool/spend/
      storage quotas are enforced; overload returns bounded retry guidance.
- [ ] Idempotency semantics include tenant, route, canonical body, retention,
      conflict behavior, and concurrent requests.
- [ ] Errors expose stable codes and correlation IDs without secrets, tenant
      existence, paths, SQL, tool output, or hidden answers.
- [ ] Proxy forwarding trust is off or restricted to explicit platform proxies;
      ingress overwrites spoofable forwarding/identity headers.
- [ ] `/readyz` and `/metrics` are private; health does not expose dependency or
      secret detail; metric labels are bounded and non-sensitive.
- [ ] Work and operational probes have separately bounded concurrency; SIGTERM
      fails readiness before admission closes and the supervisor deadline is
      longer than the configured work-drain deadline.
- [ ] Drain expiry cancels and reaps every registered evidence, benchmark
      worker, and nested candidate process group before DB/runtime-lock release;
      spawn-at-cancel and SIGTERM-ignoring child tests pass.
- [ ] Custom workers run inside a supervisor-owned per-job cgroup/container;
      deliberate fork/`setsid()` escape tests prove the kernel job boundary is
      empty before replacement work starts.
- [ ] One service owns each SQLite data directory; crash recovery is tested to
      fail interrupted idempotency keys closed, release only reserved budget,
      preserve consumed budget, and advance lease fencing tokens.

## 9. Container, host, and supply chain

- [ ] Application and proxy images are pinned by digest; CI emits verified SBOM,
      provenance/signature, license result, and vulnerability result.
- [ ] Runtime is non-root, root filesystem read-only, the application drops all
      capabilities, the proxy retains only a reviewed `NET_BIND_SERVICE`, and
      both use `no-new-privileges`, bounded tmpfs, dedicated persistent data,
      process/CPU/memory/file limits, and graceful termination.
- [ ] Only proxy is reachable; application, metrics, readiness, DB, workers, and
      secret manager follow least-privilege network policy.
- [ ] TLS, approved ciphers/policy, certificate rotation, workload identity,
      ingress authentication/rate limiting, and trusted proxy chain are tested.
- [ ] Secrets use file/credential delivery, never images/env/args/logs; file
      owner/mode, reload behavior, rotation, and break-glass access are proven.
- [ ] `docker compose config`, Docker build/health, Caddy validation, systemd
      verify/security, and deployment-policy checks pass on target versions.
- [ ] Host/kernel/container runtime are patched and monitored; debug endpoints,
      package managers, shells where unnecessary, host mounts/sockets, and
      privileged mode are absent.

## 10. Observability and SLOs

- [ ] Structured logs, audit, metrics, and traces correlate via bounded IDs and
      redact tokens, keys, prompts, hidden answers, paths, receipt bodies, and
      tool output.
- [ ] Dashboards cover ingress, queue/controller, evidence/learning, DB/WAL/disk,
      external tools, canary, outcomes, backup age, and restore-proof age.
- [ ] SLOs in the runbook are approved or replaced with measured workload targets;
      external-agent runtime is separate from controller availability/latency.
- [ ] Multi-window error-budget alerts, paging routes, escalation, maintenance,
      overload exclusions, and telemetry-loss behavior are tested.
- [ ] Security alerts cover auth/cross-tenant probes, receipt/replay/key anomalies,
      signing rate, benchmark access, promotion/rollback, audit export, and secret
      access.
- [ ] Synthetic decision, deliberately failing promotion, canary, and rollback
      probes run continuously without touching real side-effecting tools.

## 11. Backup, restore, and disaster recovery

- [ ] Backup uses SQLite-consistent API and includes every manifest/artifact,
      schema, service version, active/rollback pointers, checksums, and signed
      manifest.
- [ ] Backup is encrypted, access-separated, immutable/versioned, uploaded to
      another failure domain at an interval meeting RPO, and continuously alerted.
- [ ] Restore into an empty isolated environment verifies signature/checksum,
      DB integrity, audit-event sequence and payload hashes, any external audit
      chain, object hashes, tenants, budgets, nonce ledger, leases, model
      pointers, key IDs, and external side-effect reconciliation.
- [ ] Quarterly production-shaped restore proves RPO <= 15 minutes and RTO <= 60
      minutes, or approved SLOs are updated from measured reality.
- [ ] Region/host/storage loss, corrupt backup, compromised backup credentials,
      old-schema backup, key-unavailable restore, and legal retention are tested.

## 12. Incident readiness

- [ ] 24x7 paging and named incident commander/security/privacy/model/platform
      escalation paths exist.
- [ ] Runbooks cover no-ready instances, overload, disk/DB corruption, cross-
      tenant exposure, signing-key compromise, replay spike, benchmark leak/data
      poisoning, unsafe promotion, external side effect, and bad deploy.
- [ ] Operators can independently freeze admissions, signing/ingestion, learning,
      promotion, a tenant/principal/tool/key, and canary while preserving audit.
- [ ] Break-glass is short-lived, approved, least-privilege, logged, tested, and
      reviewed after use.
- [ ] Tabletop exercises for key compromise, cross-tenant exposure, bad model,
      restore, and external action reconciliation have dated evidence.

## 13. Test and release proof

- [ ] Unit/property/fuzz tests cover canonicalization, constraints, search,
      scoring, receipts, RBAC, serialization, migrations, and learner gates.
- [ ] Integration tests cover real HTTP auth, persistence/restart, concurrency,
      worker process behavior, backup/restore, key rotation, canary, rollback,
      metrics, and graceful shutdown.
- [ ] Adversarial tests cover tenant escape, receipt forgery/replay, tool sandbox
      escape, hidden-set extraction, poisoning, budget races, and promotion races.
- [ ] Load/soak/chaos tests establish capacity, queue/backpressure, DB contention,
      disk behavior, memory/fd/process bounds, restart recovery, and SLO headroom.
- [ ] `python -m agent_tree_rl.cli verify`, narrow tests, full tests,
      fresh-image deployment, and staging E2E pass on the exact release digest.
- [ ] An independent reviewer closes every P0/P1; exceptions have owner, expiry,
      compensating control, and executive/security acceptance.
- [ ] Release record pins source, image, SBOM/provenance, config/schema, benchmark,
      champion, key IDs, tests, backup, rollback target, approvers, and evidence.

## 14. Final go/no-go

- [ ] All above launch-blocking items are PASS with fresh links.
- [ ] Production secrets, attested worker, hidden benchmarks, TLS/network/IAM,
      remote audit, monitoring, and backup/restore exist in the target environment.
- [ ] Canary and rollback were observed on the release candidate.
- [ ] No unresolved P0/P1, expired exception, unknown owner, missing telemetry, or
      unverifiable external dependency remains.
- [ ] Product, service, ML/controller, security, platform, and on-call owners sign
      the go/no-go record.

If any final item is not true, the correct state is **production-blocked**, even
when the code and local deployment tests pass.
