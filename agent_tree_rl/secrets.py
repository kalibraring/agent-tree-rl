"""Atomic file-backed bootstrap for local receipt keys and API tokens.

Production deployments should mount these files from a secret manager. The CLI
helpers exist for single-node bootstrap and tests.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Mapping

from .config import ConfigurationError, _secure_json
from .crypto import ReceiptSigner, ReceiptVerifier, generate_hmac_key


def load_keyring(path: Path) -> tuple[dict[str, bytes], str]:
    value = _private_json(path)
    if not isinstance(value, dict):
        raise ConfigurationError("receipt keyring must be an object")
    active = value.get("active_key_id")
    raw_keys = value.get("keys")
    if not isinstance(active, str) or not isinstance(raw_keys, dict) or active not in raw_keys:
        raise ConfigurationError("receipt keyring active key is invalid")
    keys: dict[str, bytes] = {}
    for key_id, encoded in raw_keys.items():
        if not isinstance(key_id, str) or not isinstance(encoded, str):
            raise ConfigurationError("receipt keyring entry is invalid")
        try:
            key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except ValueError as error:
            raise ConfigurationError(f"receipt key {key_id} is not base64url") from error
        if len(key) < 32:
            raise ConfigurationError(f"receipt key {key_id} is too short")
        keys[key_id] = key
    return keys, active


def receipt_signer_verifier(path: Path, *, replay_guard: object | None = None) -> tuple[ReceiptSigner, ReceiptVerifier]:
    keys, active = load_keyring(path)
    verifier = ReceiptVerifier(keys, replay_guard=replay_guard)  # type: ignore[arg-type]
    return ReceiptSigner(keys, active), verifier


def initialize_secrets(
    *, keyring_path: Path, token_path: Path, tenant_id: str = "default"
) -> dict[str, str]:
    if keyring_path.exists() or token_path.exists():
        raise FileExistsError("refusing to overwrite existing production secrets")
    initialize_keyring(keyring_path)
    tokens = {
        role: secrets.token_urlsafe(48)
        for role in ("agent", "operator", "promoter", "auditor")
    }
    _atomic_private_json(
        token_path,
        {
            hashlib.sha256(token.encode("utf-8")).hexdigest(): {
                "tenant_id": tenant_id,
                "roles": [role],
                "subject_id": f"bootstrap-{role}-"
                + hashlib.sha256(token.encode("utf-8")).hexdigest()[:12],
            }
            for role, token in tokens.items()
        },
    )
    return tokens


def initialize_keyring(path: Path) -> str:
    if path.exists():
        raise FileExistsError("refusing to overwrite existing production keyring")
    key_id = "k-" + secrets.token_hex(8)
    encoded = base64.urlsafe_b64encode(generate_hmac_key()).rstrip(b"=").decode("ascii")
    _atomic_private_json(
        path,
        {"active_key_id": key_id, "keys": {key_id: encoded}},
    )
    return key_id


def rotate_keyring(path: Path) -> str:
    keys, _ = load_keyring(path)
    key_id = "k-" + secrets.token_hex(8)
    keys[key_id] = generate_hmac_key()
    payload = {
        "active_key_id": key_id,
        "keys": {
            name: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
            for name, value in sorted(keys.items())
        },
    }
    _atomic_private_json(path, payload)
    return key_id


def _private_json(path: Path) -> object:
    return _secure_json(path)


def _atomic_private_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
