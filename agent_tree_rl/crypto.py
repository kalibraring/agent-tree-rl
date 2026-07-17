"""Authenticated, canonical receipt envelopes.

The module intentionally uses only Python's standard library.  HMAC receipts
authenticate data exchanged by trusted services that share a secret; they are
not a substitute for asymmetric identity when mutually untrusted signers are
required.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import copy
import hashlib
import hmac
import json
import math
import secrets
import time
from typing import Any, TypeAlias


JSONValue: TypeAlias = (
    None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]
)
ReplayGuard: TypeAlias = Callable[[str, str, str, int | None], bool | None]

ENVELOPE_VERSION = 1
ALGORITHM = "HS256"
_SIGNED_FIELDS = frozenset(
    {
        "version",
        "algorithm",
        "key_id",
        "purpose",
        "tenant_id",
        "issued_at",
        "expires_at",
        "nonce",
        "payload",
    }
)
_ENVELOPE_FIELDS = _SIGNED_FIELDS | {"signature"}
_DEFAULT_REPLAY_GUARD = object()


class ReceiptError(ValueError):
    """Base class for receipt failures safe to handle as rejected input."""


class InvalidEnvelopeError(ReceiptError):
    """The envelope is malformed or has unsupported semantics."""


class UnknownKeyError(ReceiptError):
    """The envelope names a key that is not in the verifier keyring."""


class InvalidSignatureError(ReceiptError):
    """The envelope signature does not authenticate its signed fields."""


class ExpiredReceiptError(ReceiptError):
    """The envelope is past its authenticated expiration time."""


class NotYetValidReceiptError(ReceiptError):
    """The envelope claims an issue time unacceptably far in the future."""


class ReplayDetectedError(ReceiptError):
    """The replay guard reports that the receipt nonce was already consumed."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON suitable for hashing and signing.

    Object keys must be strings and floats must be finite.  The returned bytes
    are stable across insertion order and contain no insignificant whitespace.
    """

    _validate_json(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # defensive: validation owns errors
        raise InvalidEnvelopeError(f"value is not canonical JSON: {exc}") from exc


def sha256_hex(value: Any) -> str:
    """Return the SHA-256 digest of a canonical JSON value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def generate_hmac_key() -> bytes:
    """Generate a 256-bit HMAC key."""

    return secrets.token_bytes(32)


def _validate_json(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    # bool is an int subclass, so it must be handled first.
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidEnvelopeError(f"{path}: non-finite floats are forbidden")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidEnvelopeError(f"{path}: JSON object keys must be strings")
            _validate_json(item, f"{path}.{key}")
        return
    raise InvalidEnvelopeError(f"{path}: unsupported JSON value {type(value).__name__}")


def _validate_keyring(keys: Mapping[str, bytes]) -> dict[str, bytes]:
    if not keys:
        raise ValueError("at least one HMAC key is required")
    result: dict[str, bytes] = {}
    for key_id, key in keys.items():
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key IDs must be nonempty strings")
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError(f"HMAC key {key_id!r} must contain at least 32 bytes")
        result[key_id] = bytes(key)
    return result


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise InvalidSignatureError("signature must be nonempty base64url text")
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(
            value + padding, altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise InvalidSignatureError("signature is not valid base64url") from exc
    if len(decoded) != hashlib.sha256().digest_size:
        raise InvalidSignatureError("signature has the wrong length")
    return decoded


def _unsigned(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {name: copy.deepcopy(envelope[name]) for name in sorted(_SIGNED_FIELDS)}


class ReceiptSigner:
    """Create signed, purpose-scoped receipt envelopes with an active key ID."""

    def __init__(
        self,
        keys: Mapping[str, bytes],
        active_key_id: str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keys = _validate_keyring(keys)
        if active_key_id not in self._keys:
            raise ValueError("active_key_id is not present in the keyring")
        self.active_key_id = active_key_id
        self._clock = clock

    def sign(
        self,
        payload: JSONValue,
        *,
        purpose: str,
        tenant_id: str,
        ttl_seconds: int | None = 300,
        issued_at: int | None = None,
        nonce: str | None = None,
    ) -> dict[str, JSONValue]:
        if not purpose or not tenant_id:
            raise ValueError("purpose and tenant_id must be nonempty")
        if ttl_seconds is not None and (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or ttl_seconds <= 0
        ):
            raise ValueError("ttl_seconds must be a positive integer or None")
        now = int(self._clock()) if issued_at is None else issued_at
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise ValueError("issued_at must be a nonnegative integer Unix timestamp")
        nonce = nonce or secrets.token_urlsafe(24)
        if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
            raise ValueError("nonce must be a nonempty string of at most 256 characters")
        _validate_json(payload)
        unsigned: dict[str, JSONValue] = {
            "version": ENVELOPE_VERSION,
            "algorithm": ALGORITHM,
            "key_id": self.active_key_id,
            "purpose": purpose,
            "tenant_id": tenant_id,
            "issued_at": now,
            "expires_at": None if ttl_seconds is None else now + ttl_seconds,
            "nonce": nonce,
            "payload": copy.deepcopy(payload),
        }
        signature = hmac.new(
            self._keys[self.active_key_id],
            canonical_json_bytes(unsigned),
            hashlib.sha256,
        ).digest()
        return {**unsigned, "signature": _b64url_encode(signature)}


class ReceiptVerifier:
    """Verify HMAC envelopes before returning a detached payload copy."""

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        clock: Callable[[], float] = time.time,
        clock_skew_seconds: int = 30,
        replay_guard: ReplayGuard | None = None,
    ) -> None:
        self._keys = _validate_keyring(keys)
        if (
            not isinstance(clock_skew_seconds, int)
            or isinstance(clock_skew_seconds, bool)
            or clock_skew_seconds < 0
        ):
            raise ValueError("clock_skew_seconds must be a nonnegative integer")
        self._clock = clock
        self.clock_skew_seconds = clock_skew_seconds
        self._replay_guard = replay_guard

    def verify(
        self,
        envelope: Mapping[str, Any],
        *,
        expected_purpose: str | None = None,
        expected_tenant_id: str | None = None,
        replay_guard: ReplayGuard | None | object = _DEFAULT_REPLAY_GUARD,
    ) -> JSONValue:
        """Authenticate and validate an envelope, then optionally consume it.

        Signature verification happens before temporal and replay checks.  This
        avoids trusting attacker-controlled expiry or nonce values.  The replay
        guard must atomically claim a ``(tenant, purpose, nonce)`` tuple and
        return ``False`` when it was already claimed.
        """

        self._validate_shape(envelope)
        key_id = envelope["key_id"]
        if key_id not in self._keys:
            raise UnknownKeyError(f"unknown key ID {key_id!r}")
        supplied = _b64url_decode(envelope["signature"])
        expected = hmac.new(
            self._keys[key_id], canonical_json_bytes(_unsigned(envelope)), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(supplied, expected):
            raise InvalidSignatureError("receipt signature verification failed")

        purpose = envelope["purpose"]
        tenant_id = envelope["tenant_id"]
        if expected_purpose is not None and purpose != expected_purpose:
            raise InvalidEnvelopeError("receipt purpose does not match the expected purpose")
        if expected_tenant_id is not None and tenant_id != expected_tenant_id:
            raise InvalidEnvelopeError("receipt tenant does not match the expected tenant")

        now = int(self._clock())
        issued_at = envelope["issued_at"]
        expires_at = envelope["expires_at"]
        if issued_at > now + self.clock_skew_seconds:
            raise NotYetValidReceiptError("receipt issue time is in the future")
        if expires_at is not None and now > expires_at + self.clock_skew_seconds:
            raise ExpiredReceiptError("receipt has expired")

        guard = (
            self._replay_guard
            if replay_guard is _DEFAULT_REPLAY_GUARD
            else replay_guard
        )
        if guard is not None:
            accepted = guard(tenant_id, purpose, envelope["nonce"], expires_at)
            if accepted is False:
                raise ReplayDetectedError("receipt nonce has already been consumed")
        return copy.deepcopy(envelope["payload"])

    @staticmethod
    def _validate_shape(envelope: Mapping[str, Any]) -> None:
        if not isinstance(envelope, Mapping):
            raise InvalidEnvelopeError("receipt envelope must be an object")
        keys = set(envelope)
        if keys != _ENVELOPE_FIELDS:
            missing = sorted(_ENVELOPE_FIELDS - keys)
            extra = sorted(keys - _ENVELOPE_FIELDS)
            raise InvalidEnvelopeError(
                f"receipt envelope fields differ; missing={missing}, extra={extra}"
            )
        if envelope["version"] != ENVELOPE_VERSION:
            raise InvalidEnvelopeError("unsupported receipt envelope version")
        if envelope["algorithm"] != ALGORITHM:
            raise InvalidEnvelopeError("unsupported receipt signature algorithm")
        for name in ("key_id", "purpose", "tenant_id", "nonce"):
            if not isinstance(envelope[name], str) or not envelope[name]:
                raise InvalidEnvelopeError(f"{name} must be a nonempty string")
        if len(envelope["nonce"]) > 256:
            raise InvalidEnvelopeError("nonce exceeds 256 characters")
        issued_at = envelope["issued_at"]
        if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0:
            raise InvalidEnvelopeError("issued_at must be a nonnegative integer")
        expires_at = envelope["expires_at"]
        if expires_at is not None:
            if (
                not isinstance(expires_at, int)
                or isinstance(expires_at, bool)
                or expires_at <= issued_at
            ):
                raise InvalidEnvelopeError("expires_at must be after issued_at")
        _validate_json(envelope["payload"])


__all__ = [
    "ALGORITHM",
    "ENVELOPE_VERSION",
    "ExpiredReceiptError",
    "InvalidEnvelopeError",
    "InvalidSignatureError",
    "JSONValue",
    "NotYetValidReceiptError",
    "ReceiptError",
    "ReceiptSigner",
    "ReceiptVerifier",
    "ReplayDetectedError",
    "ReplayGuard",
    "UnknownKeyError",
    "canonical_json_bytes",
    "generate_hmac_key",
    "sha256_hex",
]
