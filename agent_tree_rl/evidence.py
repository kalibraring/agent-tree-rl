"""Authenticated, policy-constrained subprocess evidence.

This module intentionally uses only the Python standard library.  It is not a
general command runner: callers must predeclare every executable, cwd root and
environment key that a command may use.  Receipts are authenticated with
HMAC-SHA256 so a stored result cannot be edited without detection.

HMAC authentication proves possession of the configured service key. It is not
hardware attestation, and the key must therefore live outside the controller's
security domain in a real deployment.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .crypto import ReceiptSigner, canonical_json_bytes
from .process_registry import ActiveProcessRegistry


class EvidenceError(RuntimeError):
    """Base error for invalid evidence operations."""


class PolicyViolation(EvidenceError):
    """Raised before execution when a request violates the runner policy."""


class ReceiptVerificationError(EvidenceError):
    """Raised when an authenticated receipt is malformed or fails verification."""


_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_DEFAULT_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
}
_MAX_ENV_VALUE_BYTES = 16_384
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_EXECUTABLE_HASH_TIMEOUT_SECONDS = 10.0


def canonical_json(value: Any) -> bytes:
    """Return the unique UTF-8 encoding used for hashes and signatures."""

    return canonical_json_bytes(value)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _is_within(path: Path, roots: Sequence[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _resolved_existing_directory(value: os.PathLike[str] | str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise PolicyViolation(f"not a directory: {path}")
    return path


def _resolve_executable(value: os.PathLike[str] | str) -> Path:
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise PolicyViolation(f"allowlisted executable must be absolute: {value}")
    try:
        before = os.lstat(raw)
    except OSError as exc:
        raise PolicyViolation(f"cannot inspect allowlisted executable: {raw}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise PolicyViolation(f"allowlisted executable must not be a symlink: {raw}")
    if not stat.S_ISREG(before.st_mode):
        raise PolicyViolation(f"executable is not a regular file: {raw}")
    try:
        path = raw.resolve(strict=True)
        info = path.stat()
        current = os.lstat(raw)
    except OSError as exc:
        raise PolicyViolation(f"cannot resolve allowlisted executable: {raw}") from exc
    if stat.S_ISLNK(current.st_mode) or (
        before.st_dev,
        before.st_ino,
    ) != (
        current.st_dev,
        current.st_ino,
    ):
        raise PolicyViolation(f"allowlisted executable changed while resolving: {raw}")
    if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
        raise PolicyViolation(f"allowlisted executable resolved to a different file: {raw}")
    if not stat.S_ISREG(info.st_mode):
        raise PolicyViolation(f"executable is not a regular file: {path}")
    if not os.access(path, os.X_OK):
        raise PolicyViolation(f"executable is not executable: {path}")
    return path


def _read_private_regular_file(
    path: os.PathLike[str] | str,
    *,
    max_bytes: int,
    require_private_permissions: bool,
) -> bytes:
    """Read a regular non-symlink file once, with POSIX privacy checks."""

    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = candidate.absolute()
    try:
        before = os.lstat(candidate)
    except OSError as exc:
        raise PolicyViolation(f"cannot stat private file {candidate}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PolicyViolation(f"private file must be a regular non-symlink: {candidate}")
    if require_private_permissions and os.name == "posix":
        mode = stat.S_IMODE(before.st_mode)
        if mode & 0o077:
            raise PolicyViolation(
                f"private file must deny group/world access (mode {mode:04o}): {candidate}"
            )
        if not mode & stat.S_IRUSR:
            raise PolicyViolation(f"private file is not owner-readable: {candidate}")
        if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
            raise PolicyViolation(f"private file is not owned by the worker uid: {candidate}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise PolicyViolation(f"cannot securely open private file {candidate}: {exc}") from exc
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise PolicyViolation(f"private file changed while opening: {candidate}")
        if after.st_size > max_bytes:
            raise PolicyViolation(
                f"private file exceeds {max_bytes} byte limit: {candidate}"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise PolicyViolation(
                f"private file exceeds {max_bytes} byte limit: {candidate}"
            )
        return data
    finally:
        os.close(descriptor)


def load_hmac_key(path: os.PathLike[str] | str, *, min_bytes: int = 32) -> bytes:
    """Load a private HMAC key from a 0400/0600-style file."""

    key = _read_private_regular_file(
        path,
        max_bytes=4096,
        require_private_permissions=True,
    )
    if len(key) < min_bytes:
        raise PolicyViolation(f"HMAC key must contain at least {min_bytes} bytes")
    return key


@dataclass(frozen=True)
class RunnerPolicy:
    """Immutable command policy.

    ``allowed_executables`` maps stable aliases to exact executable files.
    Commands use an alias (recommended) or one of the exact resolved paths.
    PATH lookup is never performed.
    """

    allowed_executables: Mapping[str, os.PathLike[str] | str]
    allowed_cwd_roots: Sequence[os.PathLike[str] | str]
    timeout_seconds: float = 30.0
    output_cap_bytes: int = 256 * 1024
    stdin_cap_bytes: int = 1024 * 1024
    artifact_file_cap_bytes: int = 64 * 1024 * 1024
    artifact_total_cap_bytes: int = 256 * 1024 * 1024
    artifact_hash_timeout_seconds: float = 10.0
    allowed_environment: frozenset[str] = field(default_factory=frozenset)
    fixed_environment: Mapping[str, str] = field(
        default_factory=lambda: dict(_SAFE_DEFAULT_ENV)
    )

    def __post_init__(self) -> None:
        if not self.allowed_executables:
            raise ValueError("at least one executable must be allowlisted")
        if not self.allowed_cwd_roots:
            raise ValueError("at least one cwd root must be allowlisted")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 3600:
            raise ValueError("timeout_seconds must be in (0, 3600]")
        if self.output_cap_bytes < 1024 or self.output_cap_bytes > 64 * 1024 * 1024:
            raise ValueError("output_cap_bytes must be in [1024, 64 MiB]")
        if self.stdin_cap_bytes < 0 or self.stdin_cap_bytes > 64 * 1024 * 1024:
            raise ValueError("stdin_cap_bytes must be in [0, 64 MiB]")
        if not 1024 <= self.artifact_file_cap_bytes <= 1024 * 1024 * 1024:
            raise ValueError("artifact_file_cap_bytes must be in [1 KiB, 1 GiB]")
        if not (
            self.artifact_file_cap_bytes
            <= self.artifact_total_cap_bytes
            <= 4 * 1024 * 1024 * 1024
        ):
            raise ValueError(
                "artifact_total_cap_bytes must cover one file and be at most 4 GiB"
            )
        if not 0.1 <= self.artifact_hash_timeout_seconds <= 300:
            raise ValueError("artifact_hash_timeout_seconds must be in [0.1, 300]")


@dataclass(frozen=True)
class RunResult:
    receipt: dict[str, Any]
    stdout: bytes
    stderr: bytes

    @property
    def ok(self) -> bool:
        payload = self.receipt.get("payload")
        return isinstance(payload, dict) and payload.get("outcome") == "passed"

    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


class EvidenceRunner:
    """Execute one policy-constrained command and return signed evidence."""

    def __init__(
        self,
        policy: RunnerPolicy,
        signer: ReceiptSigner,
        *,
        tenant_id: str = "system",
        receipt_ttl_seconds: int = 300,
        process_registry: ActiveProcessRegistry | None = None,
    ):
        self.policy = policy
        self.signer = signer
        if not tenant_id:
            raise ValueError("tenant_id must not be empty")
        if not isinstance(receipt_ttl_seconds, int) or receipt_ttl_seconds <= 0:
            raise ValueError("receipt_ttl_seconds must be a positive integer")
        self.tenant_id = tenant_id
        self.receipt_ttl_seconds = receipt_ttl_seconds
        self.process_registry = process_registry or ActiveProcessRegistry()
        self._executables = self._validate_executables(policy.allowed_executables)
        self._roots = tuple(
            _resolved_existing_directory(root) for root in policy.allowed_cwd_roots
        )
        self._allowed_env = frozenset(policy.allowed_environment)
        for name in self._allowed_env:
            self._validate_env_name(name)
        self._fixed_env = self._sanitize_fixed_env(policy.fixed_environment)

    @staticmethod
    def _validate_executables(
        values: Mapping[str, os.PathLike[str] | str]
    ) -> dict[str, Path]:
        resolved: dict[str, Path] = {}
        seen: set[Path] = set()
        for alias, raw_path in values.items():
            if not isinstance(alias, str) or not _KEY_ID.fullmatch(alias):
                raise PolicyViolation(f"invalid executable alias: {alias!r}")
            path = _resolve_executable(raw_path)
            if path in seen:
                raise PolicyViolation(f"executable appears under multiple aliases: {path}")
            resolved[alias] = path
            seen.add(path)
        return resolved

    @staticmethod
    def _validate_env_name(name: str) -> None:
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            raise PolicyViolation(f"invalid environment name: {name!r}")

    @classmethod
    def _sanitize_fixed_env(cls, values: Mapping[str, str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for name, value in values.items():
            cls._validate_env_name(name)
            if not isinstance(value, str) or "\x00" in value:
                raise PolicyViolation(f"invalid fixed environment value for {name}")
            if len(value.encode("utf-8")) > _MAX_ENV_VALUE_BYTES:
                raise PolicyViolation(f"fixed environment value too large for {name}")
            result[name] = value
        return result

    def _environment(self, supplied: Mapping[str, str] | None) -> dict[str, str]:
        environment = dict(self._fixed_env)
        if not supplied:
            return environment
        for name, value in supplied.items():
            self._validate_env_name(name)
            if name not in self._allowed_env:
                raise PolicyViolation(f"environment key is not allowlisted: {name}")
            if not isinstance(value, str) or "\x00" in value:
                raise PolicyViolation(f"invalid environment value for {name}")
            if len(value.encode("utf-8")) > _MAX_ENV_VALUE_BYTES:
                raise PolicyViolation(f"environment value too large for {name}")
            environment[name] = value
        return environment

    def _command(self, argv: Sequence[str]) -> tuple[list[str], Path, str]:
        if not argv:
            raise PolicyViolation("argv must not be empty")
        if not all(isinstance(item, str) and item and "\x00" not in item for item in argv):
            raise PolicyViolation("argv entries must be non-empty NUL-free strings")
        requested = argv[0]
        if requested in self._executables:
            alias = requested
            executable = self._executables[alias]
        else:
            raw = Path(requested).expanduser()
            if not raw.is_absolute():
                raise PolicyViolation(
                    f"executable must be an allowlisted alias or exact absolute path: {requested}"
                )
            executable = raw.resolve(strict=True)
            aliases = [name for name, path in self._executables.items() if path == executable]
            if len(aliases) != 1:
                raise PolicyViolation(f"executable is not allowlisted: {executable}")
            alias = aliases[0]
        return [str(executable), *argv[1:]], executable, alias

    def _cwd(self, supplied: os.PathLike[str] | str) -> Path:
        cwd = _resolved_existing_directory(supplied)
        if not _is_within(cwd, self._roots):
            raise PolicyViolation(f"cwd is outside allowlisted roots: {cwd}")
        return cwd

    def _artifact_paths(
        self, artifacts: Sequence[os.PathLike[str] | str], cwd: Path
    ) -> tuple[Path, ...]:
        result: list[Path] = []
        for raw in artifacts:
            candidate = Path(raw).expanduser()
            if not candidate.is_absolute():
                candidate = cwd / candidate
            # Resolve the parent now so a missing artifact cannot smuggle an
            # out-of-root path that appears after execution.
            parent = candidate.parent.resolve(strict=True)
            normalized = parent / candidate.name
            if not _is_within(normalized, self._roots):
                raise PolicyViolation(f"artifact is outside allowlisted roots: {normalized}")
            if normalized in result:
                raise PolicyViolation(f"duplicate artifact request: {normalized}")
            result.append(normalized)
        return tuple(result)

    def _terminate(self, process: subprocess.Popen[bytes]) -> None:
        self.process_registry.signal(process, signal.SIGKILL)

    def _collect_bounded(
        self, process: subprocess.Popen[bytes], deadline: float
    ) -> tuple[bytes, bytes, str | None, int, int]:
        selector = selectors.DefaultSelector()
        if process.stdout is None or process.stderr is None:
            self._terminate(process)
            raise RuntimeError("evidence worker pipes were not created")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        total_seen = 0
        termination: str | None = None
        kill_deadline: float | None = None

        try:
            while selector.get_map():
                now = time.monotonic()
                if termination is None and now >= deadline:
                    termination = "timeout"
                    self._terminate(process)
                    kill_deadline = now + 2.0
                if kill_deadline is not None and now >= kill_deadline:
                    break
                wait = 0.05
                if termination is None:
                    wait = max(0.0, min(wait, deadline - now))
                for key, _ in selector.select(wait):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65_536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total_seen += len(chunk)
                    room = max(0, self.policy.output_cap_bytes - sum(map(len, buffers.values())))
                    if room:
                        buffers[key.data].extend(chunk[:room])
                    if total_seen > self.policy.output_cap_bytes and termination is None:
                        termination = "output_limit"
                        self._terminate(process)
                        kill_deadline = time.monotonic() + 2.0
        finally:
            selector.close()
        # Signal every member of the exactly owned process group before artifact
        # hashing. Deliberate session escape is an external sandbox boundary.
        self._terminate(process)
        try:
            returncode = self.process_registry.kill_and_reap(
                process, timeout_seconds=2
            )
        except subprocess.TimeoutExpired:
            self._terminate(process)
            returncode = self.process_registry.kill_and_reap(
                process, timeout_seconds=2
            )
        process.stdout.close()
        process.stderr.close()
        return (
            bytes(buffers["stdout"]),
            bytes(buffers["stderr"]),
            termination,
            total_seen,
            returncode,
        )

    @staticmethod
    def _hash_artifact(
        path: Path,
        *,
        allowed_roots: Sequence[Path] | None = None,
        max_bytes: int = _MAX_EXECUTABLE_BYTES,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        deadline = (
            time.monotonic() + _EXECUTABLE_HASH_TIMEOUT_SECONDS
            if deadline is None
            else deadline
        )
        if allowed_roots is not None:
            try:
                parent = path.parent.resolve(strict=True)
            except OSError:
                return {"path": str(path), "status": "unresolvable_parent"}
            path = parent / path.name
            if not _is_within(path, allowed_roots):
                return {"path": str(path), "status": "rejected_escape"}
        try:
            before = os.lstat(path)
        except FileNotFoundError:
            return {"path": str(path), "status": "missing"}
        if stat.S_ISLNK(before.st_mode):
            return {"path": str(path), "status": "rejected_symlink"}
        if not stat.S_ISREG(before.st_mode):
            return {"path": str(path), "status": "rejected_non_regular"}
        if before.st_size > max_bytes:
            return {"path": str(path), "status": "size_limit"}
        flags = os.O_RDONLY
        for optional_flag in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
            flags |= int(getattr(os, optional_flag, 0))
        digest = hashlib.sha256()
        try:
            descriptor = os.open(path, flags)
            try:
                after = os.fstat(descriptor)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    return {"path": str(path), "status": "changed_while_opening"}
                if not stat.S_ISREG(after.st_mode):
                    return {"path": str(path), "status": "rejected_non_regular"}
                if after.st_size > max_bytes:
                    return {"path": str(path), "status": "size_limit"}
                size = 0
                remaining = max_bytes + 1
                while remaining:
                    if time.monotonic() >= deadline:
                        return {"path": str(path), "status": "hash_timeout"}
                    chunk = os.read(descriptor, min(65_536, remaining))
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    remaining -= len(chunk)
                if size > max_bytes:
                    return {"path": str(path), "status": "size_limit"}
                final = os.fstat(descriptor)
                if (
                    size != after.st_size
                    or final.st_size != after.st_size
                    or getattr(final, "st_mtime_ns", None)
                    != getattr(after, "st_mtime_ns", None)
                    or getattr(final, "st_ctime_ns", None)
                    != getattr(after, "st_ctime_ns", None)
                ):
                    return {"path": str(path), "status": "changed_while_hashing"}
            finally:
                os.close(descriptor)
        except OSError:
            return {"path": str(path), "status": "unreadable"}
        return {
            "path": str(path),
            "status": "hashed",
            "size_bytes": size,
            "sha256": digest.hexdigest(),
        }

    @staticmethod
    def _fingerprints(
        executable: Path,
        environment: Mapping[str, str],
        initial_executable_sha256: str,
    ) -> dict[str, Any]:
        host = {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
        }
        current = EvidenceRunner._hash_artifact(executable)
        current_sha256 = current.get("sha256")
        return {
            "host_sha256": sha256_bytes(canonical_json(host)),
            "environment_sha256": sha256_bytes(canonical_json(dict(environment))),
            "environment_keys": sorted(environment),
            "executable_sha256": current_sha256,
            "executable_stable": current_sha256 == initial_executable_sha256,
        }

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: os.PathLike[str] | str,
        env: Mapping[str, str] | None = None,
        stdin: bytes | str | None = None,
        artifacts: Sequence[os.PathLike[str] | str] = (),
        correlation_id: str | None = None,
    ) -> RunResult:
        """Run a command without a shell and return output plus a signed receipt."""

        command, executable, alias = self._command(argv)
        initial_executable = self._hash_artifact(executable)
        initial_executable_sha256 = initial_executable.get("sha256")
        if initial_executable.get("status") != "hashed" or not isinstance(
            initial_executable_sha256, str
        ):
            raise PolicyViolation("allowlisted executable could not be fingerprinted")
        workdir = self._cwd(cwd)
        environment = self._environment(env)
        expected_artifacts = self._artifact_paths(artifacts, workdir)
        if stdin is None:
            input_bytes = b""
        elif isinstance(stdin, str):
            input_bytes = stdin.encode("utf-8")
        elif isinstance(stdin, bytes):
            input_bytes = stdin
        else:
            raise PolicyViolation("stdin must be bytes, str, or None")
        if len(input_bytes) > self.policy.stdin_cap_bytes:
            raise PolicyViolation("stdin exceeds configured byte cap")
        if correlation_id is not None and (
            not isinstance(correlation_id, str) or len(correlation_id) > 256
        ):
            raise PolicyViolation("invalid correlation_id")

        started_wall = _utc_now()
        started = time.monotonic()
        stdout = b""
        stderr = b""
        termination: str | None = None
        total_output = 0
        returncode = -1
        spawn_error: str | None = None
        process: subprocess.Popen[bytes] | None = None
        input_stream = None
        try:
            if input_bytes:
                # A seekable anonymous file avoids blocking the parent on a
                # full stdin pipe before the timeout/output monitor starts.
                input_stream = tempfile.TemporaryFile(mode="w+b")
                input_stream.write(input_bytes)
                input_stream.seek(0)
            process = self.process_registry.spawn(
                command,
                executable=str(executable),
                cwd=str(workdir),
                env=environment,
                stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
            )
            stdout, stderr, termination, total_output, returncode = self._collect_bounded(
                process, started + self.policy.timeout_seconds
            )
        except OSError as exc:
            # The exception message may contain a host-specific executable or
            # working-directory path. Only the stable class crosses the API.
            spawn_error = type(exc).__name__
        finally:
            if process is not None:
                self.process_registry.kill_and_reap(process)
            if input_stream is not None:
                input_stream.close()

        elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
        artifact_receipts: list[dict[str, Any]] = []
        artifact_bytes_remaining = self.policy.artifact_total_cap_bytes
        artifact_deadline = (
            time.monotonic() + self.policy.artifact_hash_timeout_seconds
        )
        for path in expected_artifacts:
            if artifact_bytes_remaining <= 0:
                artifact_receipts.append(
                    {"path": str(path), "status": "aggregate_size_limit"}
                )
                continue
            per_file_limit = min(
                self.policy.artifact_file_cap_bytes,
                artifact_bytes_remaining,
            )
            artifact = self._hash_artifact(
                path,
                allowed_roots=self._roots,
                max_bytes=per_file_limit,
                deadline=artifact_deadline,
            )
            if (
                artifact.get("status") == "size_limit"
                and per_file_limit < self.policy.artifact_file_cap_bytes
            ):
                artifact["status"] = "aggregate_size_limit"
            if artifact.get("status") == "hashed":
                artifact_bytes_remaining -= int(artifact["size_bytes"])
            artifact_receipts.append(artifact)
        artifact_problem = any(item["status"] != "hashed" for item in artifact_receipts)
        fingerprints = self._fingerprints(
            executable, environment, initial_executable_sha256
        )
        if not fingerprints["executable_stable"]:
            outcome = "executable_changed"
        elif spawn_error is not None:
            outcome = "spawn_error"
        elif termination == "timeout":
            outcome = "timeout"
        elif termination == "output_limit":
            outcome = "output_limit"
        elif returncode != 0:
            outcome = "failed"
        elif artifact_problem:
            outcome = "artifact_error"
        else:
            outcome = "passed"

        payload: dict[str, Any] = {
            "receipt_type": "subprocess_evidence.v1",
            "receipt_id": str(uuid.uuid4()),
            "correlation_id": correlation_id,
            "issued_at": _utc_now(),
            "started_at": started_wall,
            "duration_ms": elapsed_ms,
            "outcome": outcome,
            "command": {
                "alias": alias,
                "argv": command,
                "argv_sha256": sha256_bytes(canonical_json(command)),
                "cwd": str(workdir),
                "shell": False,
            },
            "limits": {
                "timeout_ms": round(self.policy.timeout_seconds * 1000),
                "output_cap_bytes": self.policy.output_cap_bytes,
                "stdin_cap_bytes": self.policy.stdin_cap_bytes,
                "artifact_file_cap_bytes": self.policy.artifact_file_cap_bytes,
                "artifact_total_cap_bytes": self.policy.artifact_total_cap_bytes,
                "artifact_hash_timeout_ms": round(
                    self.policy.artifact_hash_timeout_seconds * 1000
                ),
            },
            "process": {
                "returncode": returncode,
                "termination": termination,
                "spawn_error": spawn_error,
            },
            "input": {
                "size_bytes": len(input_bytes),
                "sha256": sha256_bytes(input_bytes),
            },
            "output": {
                "observed_bytes": total_output,
                "captured_bytes": len(stdout) + len(stderr),
                "truncated": total_output > len(stdout) + len(stderr),
                "stdout_size_bytes": len(stdout),
                "stderr_size_bytes": len(stderr),
                "stdout_sha256": sha256_bytes(stdout),
                "stderr_sha256": sha256_bytes(stderr),
            },
            "artifacts": artifact_receipts,
            "fingerprints": fingerprints,
        }
        envelope = self.signer.sign(
            payload,
            purpose="subprocess-evidence",
            tenant_id=self.tenant_id,
            ttl_seconds=self.receipt_ttl_seconds,
        )
        return RunResult(receipt=envelope, stdout=stdout, stderr=stderr)


__all__ = [
    "EvidenceError",
    "PolicyViolation",
    "ReceiptVerificationError",
    "ReceiptSigner",
    "RunnerPolicy",
    "RunResult",
    "EvidenceRunner",
    "canonical_json",
    "sha256_bytes",
    "load_hmac_key",
]
