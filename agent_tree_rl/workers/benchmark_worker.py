#!/usr/bin/env python3
"""Isolated worker for deterministic private JSON benchmarks.

The worker's stdout is protocol-only: one signed aggregate receipt.  It never
emits suite inputs, expectations, candidate output, case IDs, or per-case
failures.  Deploy it under a dedicated OS identity in production.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import signal
import stat
import sys
from threading import Event
import uuid


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_tree_rl.crypto import ReceiptSigner  # noqa: E402
from agent_tree_rl.evidence import (  # noqa: E402
    EvidenceRunner,
    ReceiptSigner as SharedReceiptSigner,
    RunnerPolicy,
    canonical_json,
    load_hmac_key,
)
from agent_tree_rl.hidden_benchmark import (  # noqa: E402
    BenchmarkSecurityError,
    candidate_fingerprint,
    load_private_benchmark_for_worker,
    strict_json_loads,
)
from agent_tree_rl.process_registry import ActiveProcessRegistry  # noqa: E402


MAX_REQUEST_BYTES = 128 * 1024
ACTIVE_PROCESSES = ActiveProcessRegistry()
CANCELLED = Event()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--candidate-executable", action="append", required=True)
    parser.add_argument("--candidate-cwd-root", action="append", required=True)
    parser.add_argument("--case-timeout", type=float, required=True)
    parser.add_argument("--output-cap", type=int, required=True)
    return parser


def _resolve_executable(raw: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise BenchmarkSecurityError("candidate executable allowlist must be absolute")
    try:
        before = os.lstat(path)
        resolved = path.resolve(strict=True)
        target = resolved.stat()
        current = os.lstat(path)
    except OSError as exc:
        raise BenchmarkSecurityError(
            "candidate executable allowlist entry cannot be inspected"
        ) from exc
    if stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(current.st_mode):
        raise BenchmarkSecurityError("candidate executable allowlist rejects symlinks")
    if not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(target.st_mode):
        raise BenchmarkSecurityError(
            "candidate executable allowlist entry must be a regular file"
        )
    if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino) or (
        before.st_dev,
        before.st_ino,
    ) != (
        target.st_dev,
        target.st_ino,
    ):
        raise BenchmarkSecurityError(
            "candidate executable allowlist entry changed while resolving"
        )
    if not os.access(resolved, os.X_OK):
        raise BenchmarkSecurityError("candidate executable allowlist entry is not executable")
    return resolved


def _request() -> dict[str, object]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise BenchmarkSecurityError("worker request exceeds byte cap")
    value = strict_json_loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "protocol_version",
        "request_nonce",
        "candidate_argv",
        "candidate_cwd",
    }:
        raise BenchmarkSecurityError("worker request shape is invalid")
    if value["protocol_version"] != 1:
        raise BenchmarkSecurityError("worker protocol version is unsupported")
    nonce = value["request_nonce"]
    argv = value["candidate_argv"]
    cwd = value["candidate_cwd"]
    if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
        raise BenchmarkSecurityError("worker request nonce is invalid")
    if not isinstance(argv, list) or not argv:
        raise BenchmarkSecurityError("worker candidate argv is invalid")
    if not all(isinstance(item, str) and item and "\x00" not in item for item in argv):
        raise BenchmarkSecurityError("worker candidate argv contains an invalid item")
    if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
        raise BenchmarkSecurityError("worker candidate cwd is invalid")
    return value


def _evaluate(args: argparse.Namespace) -> dict[str, object]:
    if args.case_timeout <= 0 or args.case_timeout > 3600:
        raise BenchmarkSecurityError("case timeout is outside safe bounds")
    if not 1024 <= args.output_cap <= 16 * 1024 * 1024:
        raise BenchmarkSecurityError("candidate output cap is outside safe bounds")
    suite = load_private_benchmark_for_worker(args.benchmark)
    key = load_hmac_key(args.signing_key)
    signer = ReceiptSigner({args.key_id: key}, args.key_id)
    # Assert that EvidenceRunner and the worker use the exact same shared signer
    # implementation, preventing an accidental envelope fork.
    if ReceiptSigner is not SharedReceiptSigner:
        raise BenchmarkSecurityError("receipt signer implementation mismatch")

    allowlisted = tuple(_resolve_executable(item) for item in args.candidate_executable)
    if len(set(allowlisted)) != len(allowlisted):
        raise BenchmarkSecurityError("duplicate candidate executable allowlist entry")
    roots = tuple(Path(item).expanduser().resolve(strict=True) for item in args.candidate_cwd_root)
    if not all(root.is_dir() for root in roots):
        raise BenchmarkSecurityError("candidate cwd allowlist entry is not a directory")

    request = _request()
    requested_argv = request["candidate_argv"]
    requested_cwd = Path(request["candidate_cwd"]).expanduser().resolve(strict=True)
    if not isinstance(requested_argv, list):
        raise BenchmarkSecurityError("worker candidate argv is invalid")
    executable = Path(requested_argv[0]).expanduser()
    if not executable.is_absolute():
        raise BenchmarkSecurityError("candidate executable must be absolute")
    executable = executable.resolve(strict=True)
    if executable not in allowlisted:
        raise BenchmarkSecurityError("candidate executable is not exactly allowlisted")
    if not requested_cwd.is_dir() or not any(
        requested_cwd == root or root in requested_cwd.parents for root in roots
    ):
        raise BenchmarkSecurityError("candidate cwd is outside allowlisted roots")
    normalized_argv = [str(executable), *requested_argv[1:]]
    fingerprint = candidate_fingerprint(normalized_argv, cwd=requested_cwd)

    policy = RunnerPolicy(
        allowed_executables={"candidate": executable},
        allowed_cwd_roots=roots,
        timeout_seconds=args.case_timeout,
        output_cap_bytes=args.output_cap,
        stdin_cap_bytes=16 * 1024 * 1024,
        allowed_environment=frozenset(),
    )
    runner = EvidenceRunner(
        policy,
        signer,
        tenant_id=args.tenant_id,
        receipt_ttl_seconds=max(60, min(3600, round(args.case_timeout * 2))),
        process_registry=ACTIVE_PROCESSES,
    )
    passed = 0
    weighted_score = 0
    maximum_score = sum(case.weight_micros for case in suite.cases)
    for case in suite.cases:
        # A fresh process per case prevents candidate-local state from learning
        # earlier answers.  Only the case input crosses into that process.
        result = runner.run(
            ["candidate", *normalized_argv[1:]],
            cwd=requested_cwd,
            stdin=canonical_json({"input": case.input_value}),
            correlation_id=str(uuid.uuid4()),
        )
        case_passed = False
        if result.ok:
            try:
                candidate_response = strict_json_loads(result.stdout)
            except Exception:
                candidate_response = None
            if (
                isinstance(candidate_response, dict)
                and set(candidate_response) == {"output"}
                and canonical_json(candidate_response["output"])
                == canonical_json(case.expected_value)
            ):
                case_passed = True
        if case_passed:
            passed += 1
            weighted_score += case.weight_micros

    if candidate_fingerprint(normalized_argv, cwd=requested_cwd) != fingerprint:
        raise BenchmarkSecurityError("candidate changed during benchmark execution")

    total = len(suite.cases)
    payload: dict[str, object] = {
        "receipt_type": "hidden_benchmark.aggregate.v1",
        "receipt_id": str(uuid.uuid4()),
        "request_nonce": request["request_nonce"],
        "issued_at": _utc_now(),
        "benchmark": {
            "id": suite.benchmark_id,
            "version": suite.version,
            "suite_sha256": suite.suite_sha256,
            "case_count": total,
        },
        "candidate": {"fingerprint_sha256": fingerprint},
        "result": {
            "passed": passed,
            "failed": total - passed,
            "total": total,
            "weighted_score_micros": weighted_score,
            "max_score_micros": maximum_score,
            "normalized_score_ppm": weighted_score * 1_000_000 // maximum_score,
        },
    }
    return signer.sign(
        payload,
        purpose="hidden-benchmark-aggregate",
        tenant_id=args.tenant_id,
        ttl_seconds=300,
        nonce=request["request_nonce"],
    )


def main() -> int:
    def cancel_descendants(signum: int, _frame: object) -> None:
        del signum
        CANCELLED.set()
        # Complete comfortably inside the controller registry's minimum TERM
        # window so the outer worker is not killed before its isolated
        # candidate group receives SIGKILL.
        ACTIVE_PROCESSES.cancel_all(timeout_seconds=0.2)

    signal.signal(signal.SIGTERM, cancel_descendants)
    signal.signal(signal.SIGINT, cancel_descendants)
    try:
        args = _parser().parse_args()
        receipt = _evaluate(args)
        if CANCELLED.is_set():
            return 2
        sys.stdout.buffer.write(canonical_json(receipt) + b"\n")
        return 0
    except Exception:
        # Detailed errors may include private paths or values.  Production logs
        # should record a correlation ID and a coarse failure class only.
        sys.stderr.write("hidden benchmark worker rejected the request\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
