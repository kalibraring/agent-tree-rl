#!/usr/bin/env python3
"""Keep pyproject build/dev pins aligned with the hashed CI tooling lock."""

from __future__ import annotations

from pathlib import Path
import re
import tomllib


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXACT_REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)==(?P<version>[^\s;]+)"
)
SHA256_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)")


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _exact_pins(values: list[str], *, source: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        match = EXACT_REQUIREMENT.fullmatch(value)
        if match is None:
            raise SystemExit(f"{source} must use an exact unmarked pin: {value!r}")
        name = _normalized(match.group("name"))
        version = match.group("version")
        previous = result.setdefault(name, version)
        if previous != version:
            raise SystemExit(f"{source} contains conflicting pins for {name}")
    return result


def _logical_requirements(path: Path) -> list[str]:
    result: list[str] = []
    pending = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        result.append(pending)
        pending = ""
    if pending:
        raise SystemExit(f"{path.name} ends with an incomplete continuation")
    return result


def main() -> int:
    metadata = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    expected = _exact_pins(
        list(metadata["build-system"]["requires"]),
        source="build-system.requires",
    )
    dev = _exact_pins(
        list(metadata["project"]["optional-dependencies"]["dev"]),
        source="project.optional-dependencies.dev",
    )
    for name, version in dev.items():
        previous = expected.setdefault(name, version)
        if previous != version:
            raise SystemExit(f"pyproject.toml contains conflicting pins for {name}")

    locked: dict[str, str] = {}
    lock_path = PROJECT_ROOT / "requirements-build-ci.txt"
    for requirement in _logical_requirements(lock_path):
        if requirement.startswith("--"):
            continue
        match = EXACT_REQUIREMENT.match(requirement)
        if match is None:
            raise SystemExit(f"lock entry is not exactly pinned: {requirement!r}")
        if SHA256_HASH.search(requirement) is None:
            raise SystemExit(f"lock entry has no SHA-256 hash: {requirement!r}")
        name = _normalized(match.group("name"))
        version = match.group("version")
        if name in locked:
            raise SystemExit(f"lock contains duplicate package: {name}")
        locked[name] = version

    mismatches = [
        f"{name}: pyproject={version}, lock={locked.get(name, 'missing')}"
        for name, version in sorted(expected.items())
        if locked.get(name) != version
    ]
    if mismatches:
        raise SystemExit("build lock mismatch:\n  " + "\n  ".join(mismatches))

    print(
        f"build lock check passed: {len(expected)} direct pins and "
        f"{len(locked)} locked packages"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
