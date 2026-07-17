# Release process

Use this process for public alpha releases. It proves repository artifacts; it
does not replace target-environment production gates.

## 1. Prepare

1. Update `CHANGELOG.md`, package version, supported-version policy, and docs.
2. Confirm the working tree contains only intended public files.
3. Run the deterministic public-surface check:

   ```bash
   python3 scripts/check_public_release.py
   ```

4. Run the full local release proof:

   ```bash
   python3 -m venv .venv
   .venv/bin/python -m pip install -e ".[dev]"
   PYTHON=.venv/bin/python scripts/verify_release.sh
   ```

5. Review the exact staged diff and scan the staged index plus full Git history
   with a real secret scanner.

## 2. Build and inspect

Build both standard Python artifacts:

```bash
python3 -m pip install -e ".[dev]"
python3 -m build --no-isolation
```

The release workflow independently validates archive members and wheel metadata.

Inspect archive members and extracted strings. Reject generated state, databases,
backups, local paths, emails, credentials, hidden benchmark data, and unexpected
top-level packages.

Install the wheel and source archive in separate clean environments. In each,
run:

```bash
agent-tree-rl --version
agent-tree-rl demo --json
agent-tree-rl verify
agent-tree-rl-evidence-probe health
```

## 3. Tag

Create an annotated semantic-version tag from a green, reviewed `main` commit.
Use a cryptographically signed tag when the maintainer has a configured signing
identity; an unsigned annotated tag must remain an explicit alpha limitation:

```bash
git tag -a v0.1.0 -m "Agent Tree RL v0.1.0"
git push origin v0.1.0
```

The release workflow rebuilds the wheel and source archive and attaches them to
a GitHub release. It does not publish to PyPI.

## 4. Verify the public surface

1. Clone the tag into a new directory.
2. Run the one-minute demo and complete release preflight.
3. Compare the public tag commit with the approved local commit.
4. Inspect GitHub repository visibility, owner, default branch, description,
   topics, license, community profile, Actions result, and release assets.
5. Install from the GitHub release on another machine or clean environment.

Record failures honestly. Do not advance maturity language because the release
automation passed; product and environment evidence remain separate.
