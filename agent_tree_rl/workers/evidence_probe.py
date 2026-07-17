#!/usr/bin/env python3
"""Narrow, non-secret-reading evidence probe for the default deployment.

Production operators can replace this command with a reviewed domain-specific
wrapper. Never expose a general shell or language interpreter through the
public evidence allowlist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _open_bounded_file(relative: str) -> tuple[int, os.stat_result]:
    """Open one cwd-relative regular file without following path symlinks."""

    if not relative or "\x00" in relative:
        raise ValueError("path must be nonempty and NUL-free")
    raw = Path(relative)
    if raw.is_absolute():
        raise ValueError("only cwd-relative paths are allowed")
    parts = raw.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path must not contain dot or parent components")
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if os.open not in os.supports_dir_fd or any(
        not hasattr(os, name) for name in required_flags
    ):
        raise RuntimeError("secure relative file opening is unavailable")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags |= int(getattr(os, "O_NONBLOCK", 0))
    directory_fd = os.open(".", directory_flags)
    descriptor: int | None = None
    try:
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("path must be a regular non-symlink file")
        if metadata.st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("file exceeds probe size cap")
        return descriptor, metadata
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError("path could not be opened securely") from error
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(directory_fd)


def _sha256_file(relative: str) -> dict[str, object]:
    descriptor, opened = _open_bounded_file(relative)
    hasher = hashlib.sha256()
    size = 0
    try:
        remaining = MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            size += len(chunk)
            remaining -= len(chunk)
            hasher.update(chunk)
        if size > MAX_ARTIFACT_BYTES:
            raise ValueError("file exceeds probe size cap")
        final = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if size != opened.st_size or any(
            getattr(opened, name, None) != getattr(final, name, None)
            for name in stable_fields
        ):
            raise ValueError("file changed while hashing")
    finally:
        os.close(descriptor)
    return {"status": "ok", "size_bytes": size, "sha256": hasher.hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("health")
    digest = commands.add_parser("sha256")
    digest.add_argument("path")
    args = parser.parse_args()
    if args.command == "health":
        result = {"status": "ok", "probe": "agent-tree-rl-evidence-v1"}
    else:
        result = _sha256_file(args.path)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
