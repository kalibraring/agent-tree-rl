## Outcome

Describe the user-visible or operator-visible behavior that becomes true.

## Why

Link the issue or explain the concrete problem and scope.

## Proof

List the focused commands and artifacts that prove the change. Include first-failure evidence when fixing a defect.

```text
python3 scripts/check_public_release.py
python3 examples/synthetic_terminal.py verify
python3 -m agent_tree_rl.cli verify
```

## Security and compatibility

- Trust-boundary, authentication, privacy, or secret-handling impact:
- CLI, API, artifact, database, or deployment compatibility impact:
- Rollback path:

## Checklist

- [ ] I kept the change within the stated scope.
- [ ] I added or updated focused proof for changed behavior.
- [ ] I updated user and operator documentation where needed.
- [ ] I included no credentials, private benchmark cases, tenant data, generated state, or machine-specific paths.
- [ ] I ran the public-release scanner and inspected its result.
