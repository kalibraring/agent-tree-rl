"""Private benchmark worker protocol and aggregate receipt validation.

The controller-facing client never parses benchmark JSON.  It hashes the
opaque suite, sends a candidate request to a separate worker, and accepts only
a tightly allowlisted aggregate receipt.  The worker-only loader below reads
the suite through a non-symlink descriptor and validates deterministic cases.

Filesystem permissions cannot hide data from another process running as the
same OS user.  Production deployments must therefore run the worker under a
dedicated identity (or in a separate service/container) and grant the
controller verify-only access.  These APIs preserve that boundary; they do not
pretend same-user separation is a security control.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .crypto import ReceiptError, ReceiptVerifier
from .evidence import canonical_json, sha256_bytes
from .process_registry import ActiveProcessRegistry


class HiddenBenchmarkError(RuntimeError):
    """Base class for hidden benchmark failures."""


class BenchmarkSecurityError(HiddenBenchmarkError):
    """Raised when private data or execution policy is not safely configured."""


class BenchmarkSchemaError(HiddenBenchmarkError):
    """Raised only in the worker when a private suite is invalid."""


class BenchmarkProtocolError(HiddenBenchmarkError):
    """Raised when a worker response is malformed, leaky, stale or forged."""


MAX_BENCHMARK_BYTES = 8 * 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 512 * 1024 * 1024
MAX_CASES = 10_000
MAX_JSON_DEPTH = 64
MAX_WORKER_RESPONSE_BYTES = 64 * 1024
_PAYLOAD_TOP_LEVEL = {
    "receipt_type",
    "receipt_id",
    "request_nonce",
    "issued_at",
    "benchmark",
    "candidate",
    "result",
}
_BENCHMARK_RECEIPT_KEYS = {"id", "version", "suite_sha256", "case_count"}
_CANDIDATE_RECEIPT_KEYS = {"fingerprint_sha256"}
_RESULT_RECEIPT_KEYS = {
    "passed",
    "failed",
    "total",
    "weighted_score_micros",
    "max_score_micros",
    "normalized_score_ppm",
}
_FORBIDDEN_RESPONSE_KEYS = {
    "case",
    "cases",
    "case_id",
    "expect",
    "expected",
    "input",
    "output",
    "prompt",
    "answer",
    "failure",
    "failures",
    "details",
    "stdout",
    "stderr",
}
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(data: bytes | str) -> Any:
    try:
        value = json.loads(
            data,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_object,
        )
        _validate_json_depth(value)
        canonical_json(value)
        return value
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        RecursionError,
    ) as exc:
        raise BenchmarkSchemaError(f"invalid deterministic JSON: {exc}") from exc


def _validate_json_depth(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise BenchmarkSchemaError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise BenchmarkSchemaError("JSON object keys must be strings")
            _validate_json_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_depth(child, depth=depth + 1)


def _secure_read(
    raw_path: os.PathLike[str] | str,
    *,
    max_bytes: int,
    private_permissions: bool,
) -> tuple[Path, bytes]:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = path.absolute()
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise BenchmarkSecurityError(f"cannot stat protected file {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise BenchmarkSecurityError(
            f"protected file must be a regular non-symlink: {path}"
        )
    if private_permissions and os.name == "posix":
        mode = stat.S_IMODE(before.st_mode)
        if mode & 0o077:
            raise BenchmarkSecurityError(
                f"protected file must be 0400/0600-style, got {mode:04o}: {path}"
            )
        if not mode & stat.S_IRUSR:
            raise BenchmarkSecurityError(f"protected file is not owner-readable: {path}")
        if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
            raise BenchmarkSecurityError(f"protected file owner does not match worker uid: {path}")
    if before.st_size > max_bytes:
        raise BenchmarkSecurityError(f"protected file exceeds {max_bytes} bytes: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BenchmarkSecurityError(f"cannot securely open {path}: {exc}") from exc
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise BenchmarkSecurityError(f"protected file changed while opening: {path}")
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
            raise BenchmarkSecurityError(f"protected file exceeds {max_bytes} bytes: {path}")
        return path.resolve(strict=True), data
    finally:
        os.close(descriptor)


def _validate_private_metadata(
    raw_path: os.PathLike[str] | str, *, max_bytes: int
) -> Path:
    """Validate a protected file without copying its content into this process."""

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = path.absolute()
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise BenchmarkSecurityError(f"cannot stat protected file {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BenchmarkSecurityError(f"protected file must be a regular non-symlink: {path}")
    if info.st_size > max_bytes:
        raise BenchmarkSecurityError(f"protected file exceeds {max_bytes} bytes: {path}")
    if os.name == "posix":
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077 or not mode & stat.S_IRUSR:
            raise BenchmarkSecurityError(
                f"protected file must be owner-readable and group/world denied: {path}"
            )
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise BenchmarkSecurityError(f"protected file owner does not match worker uid: {path}")
    return path.resolve(strict=True)


def _run_worker_bounded(
    command: Sequence[str],
    *,
    request: bytes,
    cwd: Path,
    timeout_seconds: float,
    process_registry: ActiveProcessRegistry,
) -> tuple[bytes, int, str | None]:
    """Run the trusted worker with a hard combined-output and wall-time cap."""

    input_file = tempfile.TemporaryFile(mode="w+b")
    input_file.write(request)
    input_file.seek(0)
    process: subprocess.Popen[bytes] | None = None
    try:
        process = process_registry.spawn(
            list(command),
            stdin=input_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            shell=False,
            close_fds=True,
        )
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("benchmark worker pipes were not created")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, True)
        selector.register(process.stderr, selectors.EVENT_READ, False)
        stdout = bytearray()
        observed = 0
        termination: str | None = None
        deadline = time.monotonic() + timeout_seconds
        kill_deadline: float | None = None
        try:
            while selector.get_map():
                now = time.monotonic()
                if termination is None and now >= deadline:
                    termination = "timeout"
                    process_registry.signal(process, signal.SIGKILL)
                    kill_deadline = now + 2
                if kill_deadline is not None and now >= kill_deadline:
                    break
                for key, _ in selector.select(0.05):
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    observed += len(chunk)
                    if key.data and len(stdout) < MAX_WORKER_RESPONSE_BYTES:
                        stdout.extend(chunk[: MAX_WORKER_RESPONSE_BYTES - len(stdout)])
                    if observed > MAX_WORKER_RESPONSE_BYTES and termination is None:
                        termination = "output_limit"
                        process_registry.signal(process, signal.SIGKILL)
                        kill_deadline = time.monotonic() + 2
        finally:
            selector.close()
        process_registry.signal(process, signal.SIGKILL)
        returncode = process_registry.kill_and_reap(process, timeout_seconds=2)
        process.stdout.close()
        process.stderr.close()
        return bytes(stdout), returncode, termination
    finally:
        if process is not None:
            process_registry.kill_and_reap(process, timeout_seconds=2)
        input_file.close()


def opaque_suite_digest(path: os.PathLike[str] | str) -> str:
    """Hash a private suite without deserializing it in the controller."""

    _, data = _secure_read(
        path, max_bytes=MAX_BENCHMARK_BYTES, private_permissions=True
    )
    return sha256_bytes(data)


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    input_value: Any
    expected_value: Any
    weight_micros: int


@dataclass(frozen=True)
class PrivateBenchmark:
    benchmark_id: str
    version: int
    suite_sha256: str
    cases: tuple[BenchmarkCase, ...]


def load_private_benchmark_for_worker(
    path: os.PathLike[str] | str,
) -> PrivateBenchmark:
    """Worker-only private loader.

    Controllers should call :func:`opaque_suite_digest` and launch the worker;
    this function necessarily returns expectations and must not be imported by
    controller code.
    """

    _, raw = _secure_read(path, max_bytes=MAX_BENCHMARK_BYTES, private_permissions=True)
    root = strict_json_loads(raw)
    if not isinstance(root, dict) or set(root) != {"schema_version", "benchmark_id", "cases"}:
        raise BenchmarkSchemaError(
            "suite must contain exactly schema_version, benchmark_id, and cases"
        )
    version = root["schema_version"]
    benchmark_id = root["benchmark_id"]
    raw_cases = root["cases"]
    if version != 1:
        raise BenchmarkSchemaError("unsupported benchmark schema_version")
    if not isinstance(benchmark_id, str) or not _SAFE_IDENTIFIER.fullmatch(benchmark_id):
        raise BenchmarkSchemaError("invalid benchmark_id")
    if not isinstance(raw_cases, list) or not raw_cases or len(raw_cases) > MAX_CASES:
        raise BenchmarkSchemaError(f"cases must contain 1..{MAX_CASES} entries")

    cases: list[BenchmarkCase] = []
    seen: set[str] = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict) or set(raw_case) != {
            "id",
            "input",
            "expected",
            "weight_micros",
        }:
            raise BenchmarkSchemaError(
                "each case must contain exactly id, input, expected, and weight_micros"
            )
        case_id = raw_case["id"]
        weight = raw_case["weight_micros"]
        if not isinstance(case_id, str) or not _SAFE_IDENTIFIER.fullmatch(case_id):
            raise BenchmarkSchemaError("invalid case id")
        if case_id in seen:
            raise BenchmarkSchemaError(f"duplicate case id: {case_id}")
        if isinstance(weight, bool) or not isinstance(weight, int) or not (1 <= weight <= 10**12):
            raise BenchmarkSchemaError("weight_micros must be an integer in [1, 10^12]")
        seen.add(case_id)
        cases.append(
            BenchmarkCase(
                case_id=case_id,
                input_value=raw_case["input"],
                expected_value=raw_case["expected"],
                weight_micros=weight,
            )
        )
    return PrivateBenchmark(
        benchmark_id=benchmark_id,
        version=version,
        suite_sha256=sha256_bytes(raw),
        cases=tuple(cases),
    )


def candidate_fingerprint(
    argv: Sequence[str], *, cwd: os.PathLike[str] | str | None = None
) -> str:
    """Bind a receipt to argv and all existing regular-file argv members."""

    if not argv or not all(isinstance(item, str) and item and "\x00" not in item for item in argv):
        raise BenchmarkSecurityError("candidate argv must contain NUL-free strings")
    executable = Path(argv[0]).expanduser()
    if not executable.is_absolute():
        raise BenchmarkSecurityError("candidate executable must be an absolute path")
    executable = executable.resolve(strict=True)
    workdir = Path(cwd).expanduser().resolve(strict=True) if cwd is not None else None
    manifest: list[dict[str, Any]] = []
    normalized = [str(executable), *argv[1:]]
    for index, item in enumerate(normalized):
        candidate = Path(item).expanduser()
        if not candidate.is_absolute():
            if workdir is None:
                continue
            candidate = workdir / candidate
        try:
            info = os.lstat(candidate)
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise BenchmarkSecurityError("candidate file arguments must not be symlinks")
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_size > MAX_CANDIDATE_FILE_BYTES:
            raise BenchmarkSecurityError("candidate file argument exceeds fingerprint cap")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        digest = hashlib.sha256()
        size = 0
        try:
            opened = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise BenchmarkSecurityError("candidate file changed while fingerprinting")
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_CANDIDATE_FILE_BYTES:
                    raise BenchmarkSecurityError(
                        "candidate file argument exceeds fingerprint cap"
                    )
                digest.update(chunk)
        finally:
            os.close(descriptor)
        manifest.append(
            {
                "argv_index": index,
                "path": str(candidate.resolve(strict=True)),
                "size_bytes": size,
                "sha256": digest.hexdigest(),
            }
        )
    return sha256_bytes(canonical_json({"argv": normalized, "files": manifest}))


def _walk_response_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise BenchmarkProtocolError("worker response contains a non-string key")
            if key.casefold() in _FORBIDDEN_RESPONSE_KEYS:
                raise BenchmarkProtocolError(f"worker response contains forbidden key: {key}")
            _walk_response_keys(child)
    elif isinstance(value, list):
        for child in value:
            _walk_response_keys(child)


def validate_aggregate_receipt(
    receipt: Mapping[str, Any],
    *,
    verifier: ReceiptVerifier,
    expected_tenant_id: str,
    expected_nonce: str,
    expected_suite_sha256: str,
    expected_candidate_fingerprint: str,
) -> dict[str, Any]:
    """Reject forged, replayed, leaky, or internally inconsistent responses."""

    if not isinstance(receipt, dict):
        raise BenchmarkProtocolError("worker response must be a JSON object")
    _walk_response_keys(receipt)
    try:
        verified = verifier.verify(
            receipt,
            expected_purpose="hidden-benchmark-aggregate",
            expected_tenant_id=expected_tenant_id,
        )
    except ReceiptError as exc:
        raise BenchmarkProtocolError("worker receipt authentication failed") from exc
    if not isinstance(verified, dict) or set(verified) != _PAYLOAD_TOP_LEVEL:
        raise BenchmarkProtocolError("worker payload has unexpected top-level fields")
    if verified.get("receipt_type") != "hidden_benchmark.aggregate.v1":
        raise BenchmarkProtocolError("unexpected worker receipt type")
    if verified.get("request_nonce") != expected_nonce:
        raise BenchmarkProtocolError("worker receipt nonce mismatch (replay or cross-talk)")

    benchmark = verified.get("benchmark")
    candidate = verified.get("candidate")
    result = verified.get("result")
    if not isinstance(benchmark, dict) or set(benchmark) != _BENCHMARK_RECEIPT_KEYS:
        raise BenchmarkProtocolError("invalid aggregate benchmark metadata")
    if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_RECEIPT_KEYS:
        raise BenchmarkProtocolError("invalid aggregate candidate metadata")
    if not isinstance(result, dict) or set(result) != _RESULT_RECEIPT_KEYS:
        raise BenchmarkProtocolError("invalid aggregate result")
    if benchmark.get("suite_sha256") != expected_suite_sha256:
        raise BenchmarkProtocolError("private suite digest mismatch")
    if candidate.get("fingerprint_sha256") != expected_candidate_fingerprint:
        raise BenchmarkProtocolError("candidate fingerprint mismatch")

    integer_fields = (
        "passed",
        "failed",
        "total",
        "weighted_score_micros",
        "max_score_micros",
        "normalized_score_ppm",
    )
    if any(isinstance(result.get(key), bool) or not isinstance(result.get(key), int) for key in integer_fields):
        raise BenchmarkProtocolError("aggregate counters and scores must be integers")
    if min(result[key] for key in integer_fields) < 0:
        raise BenchmarkProtocolError("aggregate counters and scores must be non-negative")
    if result["passed"] + result["failed"] != result["total"]:
        raise BenchmarkProtocolError("aggregate case counts are inconsistent")
    if benchmark.get("case_count") != result["total"]:
        raise BenchmarkProtocolError("benchmark case_count does not match result total")
    if result["weighted_score_micros"] > result["max_score_micros"]:
        raise BenchmarkProtocolError("aggregate weighted score exceeds maximum")
    if not 0 <= result["normalized_score_ppm"] <= 1_000_000:
        raise BenchmarkProtocolError("normalized score is outside [0, 1_000_000]")
    expected_ppm = (
        result["weighted_score_micros"] * 1_000_000
        // result["max_score_micros"]
        if result["max_score_micros"]
        else 0
    )
    if result["normalized_score_ppm"] != expected_ppm:
        raise BenchmarkProtocolError("normalized score is inconsistent")
    return dict(receipt)


@dataclass(frozen=True)
class HiddenBenchmarkConfig:
    worker_script: os.PathLike[str] | str
    benchmark_path: os.PathLike[str] | str
    signing_key_path: os.PathLike[str] | str
    key_id: str
    candidate_executables: Sequence[os.PathLike[str] | str]
    candidate_cwd_roots: Sequence[os.PathLike[str] | str]
    python_executable: os.PathLike[str] | str = sys.executable
    case_timeout_seconds: float = 10.0
    candidate_output_cap_bytes: int = 64 * 1024
    worker_timeout_seconds: float = 300.0
    worker_tenant_id: str = "hidden-benchmark-worker"


class HiddenBenchmarkClient:
    """Controller-side opaque benchmark client."""

    def __init__(
        self,
        config: HiddenBenchmarkConfig,
        verifier: ReceiptVerifier,
        *,
        process_registry: ActiveProcessRegistry | None = None,
    ):
        self.config = config
        self.verifier = verifier
        self.process_registry = process_registry or ActiveProcessRegistry()
        raw_worker = Path(config.worker_script).expanduser()
        if not raw_worker.is_absolute():
            raw_worker = raw_worker.absolute()
        try:
            worker_info = os.lstat(raw_worker)
        except OSError as exc:
            raise BenchmarkSecurityError(f"cannot stat worker script: {exc}") from exc
        if stat.S_ISLNK(worker_info.st_mode) or not stat.S_ISREG(worker_info.st_mode):
            raise BenchmarkSecurityError("worker script must be a regular non-symlink")
        self.worker_script = raw_worker.resolve(strict=True)
        self.benchmark_path, _ = _secure_read(
            config.benchmark_path,
            max_bytes=MAX_BENCHMARK_BYTES,
            private_permissions=True,
        )
        self.signing_key_path = _validate_private_metadata(
            config.signing_key_path, max_bytes=4096  # gitleaks:allow
        )
        self.python_executable = Path(config.python_executable).expanduser().resolve(strict=True)
        if not self.python_executable.is_file() or not os.access(self.python_executable, os.X_OK):
            raise BenchmarkSecurityError("worker Python executable is not executable")
        if not config.candidate_executables or not config.candidate_cwd_roots:
            raise BenchmarkSecurityError("candidate executable and cwd allowlists are required")
        self.allowed_executables = tuple(
            Path(item).expanduser().resolve(strict=True) for item in config.candidate_executables
        )
        self.cwd_roots = tuple(
            Path(item).expanduser().resolve(strict=True) for item in config.candidate_cwd_roots
        )
        if config.case_timeout_seconds <= 0 or config.worker_timeout_seconds <= 0:
            raise BenchmarkSecurityError("benchmark timeouts must be positive")
        if not config.worker_tenant_id:
            raise BenchmarkSecurityError("worker_tenant_id must not be empty")
        if not 1024 <= config.candidate_output_cap_bytes <= 16 * 1024 * 1024:
            raise BenchmarkSecurityError("candidate output cap must be in [1 KiB, 16 MiB]")

    def _validate_candidate(self, argv: Sequence[str], cwd: os.PathLike[str] | str) -> tuple[list[str], Path]:
        if not argv:
            raise BenchmarkSecurityError("candidate argv is empty")
        executable = Path(argv[0]).expanduser()
        if not executable.is_absolute():
            raise BenchmarkSecurityError("candidate executable must be absolute")
        executable = executable.resolve(strict=True)
        if executable not in self.allowed_executables:
            raise BenchmarkSecurityError("candidate executable is not exactly allowlisted")
        workdir = Path(cwd).expanduser().resolve(strict=True)
        if not workdir.is_dir() or not any(
            workdir == root or root in workdir.parents for root in self.cwd_roots
        ):
            raise BenchmarkSecurityError("candidate cwd is outside allowlisted roots")
        if not all(isinstance(arg, str) and arg and "\x00" not in arg for arg in argv):
            raise BenchmarkSecurityError("candidate argv contains an invalid value")
        return [str(executable), *argv[1:]], workdir

    def run(
        self,
        candidate_argv: Sequence[str],
        *,
        candidate_cwd: os.PathLike[str] | str,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        argv, cwd = self._validate_candidate(candidate_argv, candidate_cwd)
        request_nonce = nonce or str(uuid.uuid4())
        if not isinstance(request_nonce, str) or not request_nonce or len(request_nonce) > 256:
            raise BenchmarkSecurityError("invalid request nonce")
        suite_digest = opaque_suite_digest(self.benchmark_path)
        fingerprint = candidate_fingerprint(argv, cwd=cwd)
        request = canonical_json(
            {"protocol_version": 1, "request_nonce": request_nonce, "candidate_argv": argv, "candidate_cwd": str(cwd)}
        )
        worker_command = [
            str(self.python_executable),
            str(self.worker_script),
            "--benchmark",
            str(self.benchmark_path),
            "--signing-key",
            str(self.signing_key_path),
            "--key-id",
            self.config.key_id,
            "--tenant-id",
            self.config.worker_tenant_id,
            "--case-timeout",
            str(self.config.case_timeout_seconds),
            "--output-cap",
            str(self.config.candidate_output_cap_bytes),
        ]
        for executable in self.allowed_executables:
            worker_command.extend(("--candidate-executable", str(executable)))
        for root in self.cwd_roots:
            worker_command.extend(("--candidate-cwd-root", str(root)))
        stdout, returncode, termination = _run_worker_bounded(
            worker_command,
            request=request,
            cwd=self.worker_script.parent.parent,
            timeout_seconds=self.config.worker_timeout_seconds,
            process_registry=self.process_registry,
        )
        if termination == "timeout":
            raise BenchmarkProtocolError("hidden benchmark worker timed out")
        if termination == "output_limit":
            raise BenchmarkProtocolError("hidden benchmark worker response exceeded cap")
        if returncode != 0:
            # Never echo stderr: worker diagnostics can contain private data.
            raise BenchmarkProtocolError(
                f"hidden benchmark worker failed with exit code {returncode}"
            )
        try:
            receipt = strict_json_loads(stdout)
        except BenchmarkSchemaError as exc:
            raise BenchmarkProtocolError("hidden benchmark worker returned invalid JSON") from exc
        return validate_aggregate_receipt(
            receipt,
            verifier=self.verifier,
            expected_tenant_id=self.config.worker_tenant_id,
            expected_nonce=request_nonce,
            expected_suite_sha256=suite_digest,
            expected_candidate_fingerprint=fingerprint,
        )


__all__ = [
    "HiddenBenchmarkError",
    "BenchmarkSecurityError",
    "BenchmarkSchemaError",
    "BenchmarkProtocolError",
    "BenchmarkCase",
    "PrivateBenchmark",
    "HiddenBenchmarkConfig",
    "HiddenBenchmarkClient",
    "load_private_benchmark_for_worker",
    "opaque_suite_digest",
    "candidate_fingerprint",
    "validate_aggregate_receipt",
    "strict_json_loads",
]
