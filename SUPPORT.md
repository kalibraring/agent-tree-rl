# Support

Agent Tree RL is community-supported experimental software with no support SLA.

## Where to ask

- Use GitHub Discussions for setup questions, design proposals, and examples.
- Use GitHub Issues for reproducible defects and bounded feature requests.
- Use private vulnerability reporting for security concerns; see
  [SECURITY.md](SECURITY.md).

Before filing a bug, run:

```bash
python3 -m agent_tree_rl.cli --version
python3 -m agent_tree_rl.cli doctor
python3 -m agent_tree_rl.cli verify
```

Include the operating system, Python version, command, sanitized error, expected
behavior, and smallest reproduction. Remove tokens, keys, tenant content, hidden
benchmark material, receipts, and machine-specific paths.

The maintainer may close requests that require an unsupported production claim,
weaken a security boundary, or lack a reproducible contract.
