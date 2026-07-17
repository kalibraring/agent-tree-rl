# Open-source and product plan

This plan separates a healthy public project from a useful product. Open-source
hygiene makes the work inspectable and contributable; product work makes it solve
a repeatable user problem. Neither substitutes for production environment proof.

## Product statement

**Target user:** agent-platform engineers responsible for costly or high-impact
automated decisions.

**Job:** turn structured multi-agent deliberation into an auditable decision and
change routing policy only after independent evidence proves improvement.

**Current release:** an experimental reference implementation using one synthetic
Android fixture. It proves controller mechanics, not real-agent improvement.

**North-star measure:** independently verified successful decisions per unit cost
relative to a frozen baseline.

## Portfolio fit

The public portfolio review placed the reusable controller in `kalibraring`,
whose existing public work is closest to libraries and command-line systems.
The other portfolios suggest optional integrations without coupling the core
project to them:

- `kaskilling` can later host a thin agent-skill wrapper around a stable release;
- `katooling` can later host a browser playground or trace visualizer;
- `kaplicationing` had no public repository surface during the launch review, so
  no packaging or deployment assumption depends on it.

This repository remains the source of truth for the engine, control plane,
formats, tests, and releases. Integrations consume versioned public contracts;
they do not fork controller logic.

## Good open-source project checklist

### Public foundation

- [x] Clear name, owner, description, alpha version, and MIT license.
- [x] README explains value, target user, limitations, quickstart, and proof.
- [x] Usage, API, architecture, security, operations, and design docs have one
  obvious index.
- [x] Contribution, conduct, support, governance, security, changelog, and roadmap
  policies exist.
- [x] Structured issue forms, pull-request template, CODEOWNERS, and dependency
  update configuration exist.
- [x] Generated state, secrets, keys, databases, backups, and build artifacts are
  ignored.
- [x] A deterministic public-release scanner checks paths, credentials, generated
  files, and local Markdown links.
- [x] Pull-request CI tests Python 3.11–3.13 and builds an installable package.
- [x] Tag automation produces wheel and source artifacts without requiring PyPI
  credentials.

### Maintainer operations

- [ ] Protect `main`; require CI, review, resolved conversations, and linear
  history.
- [ ] Enable private vulnerability reporting and GitHub Discussions.
- [ ] Enable GitHub secret scanning, push protection, Dependabot alerts, and
  dependency review where the plan permits.
- [ ] Add OpenSSF Scorecard and CodeQL after the public repository exists.
- [ ] Produce SBOM, artifact attestations, checksums, and signed releases.
- [ ] Publish a supported-version and release cadence decision after external use.
- [ ] Recruit a second maintainer or document an archive/succession trigger.

### Release evidence

- [x] Exact source tests and controller acceptance proof pass.
- [x] Wheel installs and runs in a clean environment.
- [x] Source archive installs and runs in a clean environment.
- [ ] Final Git index and complete history pass a real secret scanner.
- [ ] Git archive, wheel, source archive, and container layers contain no private
  paths, emails, credentials, generated state, or hidden benchmark material.
- [ ] A fresh public clone passes the one-minute demo and full release preflight.
- [ ] One external user completes the quickstart without maintainer assistance.

## Good product checklist

### Problem and experience

- [x] Target user, job, use cases, exclusions, and measurable outcome are explicit.
- [x] One-command synthetic demo reaches meaningful output in under a minute.
- [x] Authenticated local lifecycle has a copy-ready guide and exact success
  artifacts.
- [ ] User-defined scenario/tree manifest with validation and compatibility rules.
- [ ] Real agent adapter and evidence-worker interfaces.
- [ ] One provider-neutral integration and one custom-scenario tutorial.
- [ ] CLI/API support for submit, inspect, cancel, train, evaluate, promote,
  rollback, and audit without core-code edits.
- [ ] Actionable error messages and a generated configuration reference.

### Trust and operations

- [x] Hard constraints precede reward and learned policy cannot rewrite governance.
- [x] Tenant, receipt, replay, budget, lease, promotion, rollback, and recovery
  mechanics have adversarial tests.
- [ ] Independent attested workers and proprietary hidden suites.
- [ ] Workload identity, KMS/secret delivery, TLS ingress, rate limiting, and
  immutable remote audit.
- [ ] Queue, latency, budget, benchmark, backup, canary, and outcome observability.
- [ ] Off-site encrypted backup plus measured restore, RPO, and RTO drills.
- [ ] Two pilots, baseline comparison, seven-day soak, and bad-promotion exercise.

### Adoption and sustainability

- [ ] Track time to first demo, first custom scenario, install success, appropriate
  abstention, verified outcomes, cost delta, and rollback recovery time locally.
- [ ] No phone-home telemetry by default; any optional collection is explicit and
  consent-based.
- [ ] Publish compatibility, deprecation, support, and security-response policies.
- [ ] Document packaging, deployment, and upgrade paths for supported environments.

## Execution phases

### Phase 0 — public alpha (`v0.1`)

Package the existing controller honestly, remove private/generated material, add
community and release controls, publish a clean first history, and prove the
public clone. This phase does not claim a general agent product.

**Exit:** a new user can clone, run `agent-tree-rl demo`, understand the synthetic
boundary, run verification, and find contribution/security/support information.

### Phase 1 — usable agent product (`v0.2`–`v0.3`)

Add versioned scenario and adapter contracts, real-agent integration, custom
examples, and stable inspection/control surfaces.

**Exit:** an outside user can run a new scenario and frozen agent configurations
without modifying core source.

### Phase 2 — deployable beta (`v0.5`)

Separate workers, add production identity and observability, prove upgrades and
recovery, and operate two real pilot workloads.

**Exit:** staged deployment meets defined security, SLO, canary, rollback, RPO,
and RTO evidence gates.

### Phase 3 — stable product (`v1.0`)

Stabilize public contracts and maintenance policy after external operational use.

**Exit:** compatibility, security, supply-chain, recovery, and real-outcome gates
are current, with at least one external operator and a sustainable maintainer
model.

## Reference standards

- [GitHub community profiles](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories)
- [Python Packaging User Guide](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)
- [Semantic Versioning](https://semver.org/)
