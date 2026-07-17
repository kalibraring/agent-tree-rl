"""Relocatable, content-addressed policy artifact locations."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_POLICY_BYTES = 64 * 1024 * 1024


def tenant_namespace(tenant_id: str) -> str:
    if not tenant_id:
        raise ValueError("tenant_id must not be empty")
    return hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:20]


def policy_artifact_uri(tenant_id: str, content_sha256: str) -> str:
    _digest(content_sha256)
    return (
        "policy-artifact://"
        f"{tenant_namespace(tenant_id)}/{content_sha256}.json"
    )


def policy_artifact_path(
    artifact_root: Path, tenant_id: str, content_sha256: str
) -> Path:
    _digest(content_sha256)
    return (
        artifact_root.resolve()
        / tenant_namespace(tenant_id)
        / f"{content_sha256}.json"
    )


def resolve_policy_artifact(
    artifact_root: Path,
    tenant_id: str,
    content_sha256: str,
    artifact_uri: str,
) -> Path:
    expected_uri = policy_artifact_uri(tenant_id, content_sha256)
    if artifact_uri != expected_uri:
        raise ValueError("policy artifact URI is not canonical")
    return policy_artifact_path(artifact_root, tenant_id, content_sha256)


def read_verified_policy(path: Path, expected_sha256: str) -> bytes:
    _digest(expected_sha256)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("policy artifact must be a regular non-symlink file")
    if metadata.st_size > MAX_POLICY_BYTES:
        raise ValueError("policy artifact exceeds size cap")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("policy artifact changed while opening")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_POLICY_BYTES:
                raise ValueError("policy artifact exceeds size cap")
            chunks.append(chunk)
            digest.update(chunk)
    finally:
        os.close(descriptor)
    if digest.hexdigest() != expected_sha256:
        raise ValueError("policy artifact content hash mismatch")
    return b"".join(chunks)


def _digest(value: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("content_sha256 must be 64 lowercase hexadecimal characters")
