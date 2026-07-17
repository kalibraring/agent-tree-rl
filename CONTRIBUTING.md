# Contributing

Agent Tree RL welcomes focused bug fixes, security improvements, documentation,
tests, and design proposals that preserve its governed-decision model.

## Before you start

Use a GitHub issue for a reproducible bug. Use a GitHub discussion for a larger
design or product proposal. Security vulnerabilities belong in a private report;
follow [SECURITY.md](SECURITY.md).

For substantial changes, agree on the contract before implementing it. In
particular, changes to move legality, evidence trust, benchmark semantics,
promotion, tenancy, or recovery require an explicit design discussion.

## Development setup

```bash
git clone https://github.com/kalibraring/agent-tree-rl.git
cd agent-tree-rl
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/agent-tree-rl demo
```

The runtime has no third-party Python dependencies. The optional `dev` extra
installs the pinned build and lint tooling used by the release preflight.

## Make a change

1. Create a branch from current `main`.
2. Add or update the narrowest test that proves the intended behavior.
3. Keep safety rules deterministic and outside learned policy code.
4. Preserve tenant, receipt, artifact, and idempotency boundaries.
5. Update user-facing documentation when a command or contract changes.
6. Run focused tests, then the public release preflight.

```bash
python3 -m unittest tests.test_core -v
python3 scripts/check_public_release.py
PYTHON=.venv/bin/python scripts/verify_release.sh
```

## Pull requests

A pull request should state:

- the behavior that changed;
- the proof that demonstrates it;
- security, compatibility, and operational effects;
- any evidence surface that was not available.

Keep unrelated changes out of the same pull request. Do not include generated
state, databases, backups, keys, tokens, private benchmarks, local paths, or raw
production evidence.

By contributing, you agree that your contribution is licensed under this
repository's MIT License. Add a Developer Certificate of Origin sign-off to each
commit:

```bash
git commit --signoff
```

The sign-off certifies that you have the right to submit the contribution under
the project's license. See <https://developercertificate.org/>.

## Review standard

Maintainers review correctness, tests, public API compatibility, security
boundaries, documentation, and product fit. Passing CI is required but is not
enough when a change weakens a trust boundary or makes a production claim.
