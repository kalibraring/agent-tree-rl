# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| `0.1.x` | Yes, while it is the latest minor line |
| Older versions | No |

This alpha is a reference implementation. Support for a version does not mean
the project is approved for privileged, irreversible, or safety-critical use.

## Report a vulnerability privately

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/kalibraring/agent-tree-rl/security/advisories/new>

Include the affected version, impact, reproduction, and any proposed mitigation.
Do not open a public issue for an undisclosed vulnerability. Do not include real
credentials, private benchmark answers, tenant data, or production payloads.

The maintainer aims to acknowledge a report within three business days and
provide an initial triage within seven. These are best-effort targets, not a
service-level agreement.

## Security model

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before deploying or extending
the controller. Important boundaries include:

- the committed benchmark is public and synthetic;
- HMAC receipts prove possession of a shared key, not worker independence;
- the built-in HTTP server must remain behind a hardened ingress with connection,
  header, body, concurrency, and rate limits;
- high-impact evaluation requires independently governed workers and private
  benchmarks;
- the single-node SQLite design permits one application writer;
- local bootstrap tokens and key files are development conveniences, not a
  production secret-management system.

Security-sensitive changes require focused adversarial tests and an update to
the threat model.
