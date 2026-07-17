"""Operational CLI for initialization, service, diagnostics and recovery."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import stat
import sys
from threading import Thread
from types import FrameType
from typing import Iterator

from . import __version__
from .api import serve
from .backup import create_bundle, restore_bundle
from .config import BackupSettings, Settings
from .control import ControlPlane
from .crypto import ReceiptSigner, ReceiptVerifier, generate_hmac_key
from .engine import PUCTSearch, PolicyValueModel, default_benchmark, default_scenario
from .evidence import load_hmac_key
from .hidden_benchmark import (
    HiddenBenchmarkClient,
    HiddenBenchmarkConfig,
    opaque_suite_digest,
)
from .logging_utils import configure_logging
from .metrics import Metrics
from .process_registry import ActiveProcessRegistry
from .secrets import (
    CreatedFile,
    FileIdentity,
    file_identity,
    initialize_keyring,
    initialize_secrets,
    load_keyring,
    rotate_keyring,
    unlink_created_file,
)
from .store import SQLiteStore


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
SAMPLE_BENCHMARK = PACKAGE_ROOT / "fixtures" / "sample_policy.json"
BENCHMARK_KEY_ID = "hidden-benchmark-v1"
LOGGER = logging.getLogger("agent_tree_rl.cli")


class ServiceAlreadyRunningError(RuntimeError):
    """The persistent data directory is owned by another live service."""


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be nonnegative")
    return parsed


def build_runtime(settings: Settings) -> tuple[ControlPlane, SQLiteStore]:
    process_registry = ActiveProcessRegistry()
    main_keys, active = load_keyring(settings.receipt_keys_file)
    signer = ReceiptSigner(main_keys, active)
    verifier_keys = dict(main_keys)
    benchmark_key_path = (
        settings.benchmark_signing_key_file
        or settings.data_dir / "benchmark-signing.key"
    )
    if benchmark_key_path.exists():
        benchmark_key = load_hmac_key(benchmark_key_path)
        verifier_keys[BENCHMARK_KEY_ID] = benchmark_key
    verifier = ReceiptVerifier(verifier_keys)
    store = SQLiteStore(settings.database_path, receipt_verifier=verifier)

    hidden: HiddenBenchmarkClient | None = None
    benchmark_path = settings.benchmark_file or settings.benchmark_dir / "policy.json"
    worker_script = PACKAGE_ROOT / "workers" / "benchmark_worker.py"
    if (
        benchmark_path.exists()
        and benchmark_key_path.exists()
    ):
        sample_path = SAMPLE_BENCHMARK
        if (
            sample_path.exists()
            and opaque_suite_digest(benchmark_path)
            == hashlib.sha256(sample_path.read_bytes()).hexdigest()
            and not settings.allow_sample_benchmark
        ):
            raise ValueError(
                "public sample benchmark is forbidden; provision a private suite "
                "or explicitly enable it only for local acceptance"
            )
        hidden = HiddenBenchmarkClient(
            HiddenBenchmarkConfig(
                worker_script=worker_script,
                benchmark_path=benchmark_path,
                signing_key_path=benchmark_key_path,
                key_id=BENCHMARK_KEY_ID,
                # This fixed internal candidate boundary is intentionally
                # separate from the public evidence-command allowlist.
                candidate_executables=(Path(sys.executable).resolve(),),
                candidate_cwd_roots=(PROJECT_ROOT, settings.data_dir),
                python_executable=sys.executable,
            ),
            verifier,
            process_registry=process_registry,
        )
    control = ControlPlane(
        settings=settings,
        store=store,
        signer=signer,
        verifier=verifier,
        metrics=Metrics(),
        hidden_benchmark=hidden,
        process_registry=process_registry,
    )
    return control, store


def _write_private_exclusive(
    path: Path,
    data: bytes,
    *,
    creation_log: list[CreatedFile] | None = None,
) -> FileIdentity:
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    created = (path, file_identity(os.fstat(descriptor)))
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise OSError("private-file write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        created = (path, file_identity(os.fstat(descriptor)))
        if file_identity(os.lstat(path)) != created[1]:
            raise OSError("private-file path changed while writing")
    except BaseException as error:
        try:
            created = (path, file_identity(os.fstat(descriptor)))
            unlink_created_file(created)
        except BaseException as cleanup_error:
            error.add_note(f"private-file cleanup also failed: {cleanup_error!r}")
        try:
            os.close(descriptor)
        except BaseException as close_error:
            error.add_note(f"private-file descriptor close also failed: {close_error!r}")
        raise
    try:
        os.close(descriptor)
    except BaseException as error:
        try:
            unlink_created_file(created)
        except BaseException as cleanup_error:
            error.add_note(
                f"private-file rollback after close failure also failed: {cleanup_error!r}"
            )
        raise
    if creation_log is not None:
        creation_log.append(created)
    return created[1]


def command_init(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir).expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    keyring = data_dir / "receipt-keys.json"
    token_hashes = data_dir / "api-tokens.json"
    backup_keyring = data_dir / "backup-keys.json"
    benchmark_key = data_dir / "benchmark-signing.key"
    benchmark_dir = data_dir / "benchmarks"
    destination = benchmark_dir / "policy.json"
    token_output = (
        Path(args.token_output).expanduser().resolve()
        if args.token_output
        else data_dir / "bootstrap-tokens.json"
    )
    managed_paths = (
        keyring,
        token_hashes,
        token_output,
        backup_keyring,
        benchmark_key,
        benchmark_dir,
        destination,
    )
    if len({path.resolve(strict=False) for path in managed_paths}) != len(
        managed_paths
    ):
        raise ValueError("initialization paths must be distinct")
    if benchmark_dir.resolve(strict=False) in token_output.resolve(
        strict=False
    ).parents:
        raise ValueError("token output must not be inside the benchmark directory")
    if any(path.exists() for path in managed_paths):
        raise FileExistsError("refusing to overwrite an existing initialization path")

    created_files: list[CreatedFile] = []
    created_directories: list[tuple[Path, FileIdentity, int | None]] = []
    try:
        initialize_secrets(
            keyring_path=keyring,
            token_path=token_hashes,
            plaintext_token_path=token_output,
            tenant_id=args.tenant,
            creation_log=created_files,
        )
        initialize_keyring(backup_keyring, creation_log=created_files)
        _write_private_exclusive(
            benchmark_key,
            generate_hmac_key(),
            creation_log=created_files,
        )
        benchmark_dir.mkdir(mode=0o700)
        try:
            directory_identity = file_identity(os.lstat(benchmark_dir))
        except BaseException:
            try:
                benchmark_dir.rmdir()
            except OSError:
                pass
            raise
        created_directories.append((benchmark_dir, directory_identity, None))
        directory_descriptor = os.open(
            benchmark_dir,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        created_directories[-1] = (
            benchmark_dir,
            directory_identity,
            directory_descriptor,
        )
        _write_private_exclusive(
            destination,
            SAMPLE_BENCHMARK.read_bytes(),
            creation_log=created_files,
        )
    except BaseException as error:
        for item in reversed(created_files):
            try:
                unlink_created_file(item)
            except OSError as cleanup_error:
                error.add_note(f"bootstrap file cleanup also failed: {cleanup_error!r}")
        for path, fallback_identity, descriptor in reversed(created_directories):
            try:
                current = os.lstat(path)
                expected = (
                    file_identity(os.fstat(descriptor))
                    if descriptor is not None
                    else fallback_identity
                )
                if stat.S_ISDIR(current.st_mode) and file_identity(current) == expected:
                    path.rmdir()
            except OSError:
                pass
        for _, _, descriptor in created_directories:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as close_error:
                    error.add_note(
                        f"bootstrap directory descriptor close also failed: {close_error!r}"
                    )
        raise
    for _, _, descriptor in created_directories:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                LOGGER.warning(
                    "directory descriptor close failed after initialization committed: %s",
                    error,
                )
    print(json.dumps({
        "data_dir": str(data_dir),
        "tenant_id": args.tenant,
        "token_output": str(token_output),
        "warning": (
            "Move the one-time tokens from token_output to a secret manager, "
            "then securely delete that file."
        ),
        "benchmark_warning": "The installed benchmark is a public fixture. Replace it before production.",
    }, indent=2, sort_keys=True))
    return 0


def command_demo(args: argparse.Namespace) -> int:
    """Run the built-in deterministic fixture without creating durable state."""

    scenario = default_scenario()
    result = PUCTSearch(
        scenario,
        default_benchmark(scenario),
        PolicyValueModel(),
        seed=args.seed,
    ).run(args.simulations)
    payload = {
        "demo": True,
        "fixture": scenario.name,
        "synthetic": True,
        "simulations": result.simulations,
        "status": result.final_position.terminal_status.value,
        "trajectory": [
            {
                "id": move.id,
                "kind": move.kind.value,
                "actor": move.actor,
                "text": move.text,
            }
            for move in result.trajectory
        ],
        "feasible": result.score.feasible,
        "abstained": result.abstained,
        "reward": result.score.reward,
        "hard_gate_failures": list(result.score.gate_failures),
        "notice": "Synthetic fixture only; no external agents or tools were called.",
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print("Agent Tree RL synthetic demo")
    print(f"fixture: {payload['fixture']}")
    print("selected path:")
    for index, move in enumerate(payload["trajectory"], start=1):
        print(
            f"  {index}. {move['id']} [{move['kind']}] "
            f"{move['actor']}: {move['text']}"
        )
    print(f"status: {payload['status']}")
    print(f"hard gates: {'pass' if payload['feasible'] else 'fail'}")
    print(f"reward: {payload['reward']:+.6f}")
    print(payload["notice"])
    return 0


@contextmanager
def _exclusive_service_lock(data_dir: Path) -> Iterator[None]:
    """Prevent two service writers from sharing transient operation state."""

    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(data_dir / ".service.lock", flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("service lock must be a regular file")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ServiceAlreadyRunningError(
                "another agent-tree-rl service owns this data directory"
            ) from error
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _serve_with_signal_drain(settings: Settings, control: ControlPlane) -> bool:
    previous_handlers: dict[int, signal.Handlers] = {}
    shutdown_thread: Thread | None = None

    def ready(server: object) -> None:
        nonlocal shutdown_thread

        def request_shutdown(
            signum: int,
            _frame: FrameType | None,
        ) -> None:
            nonlocal shutdown_thread
            begin_draining = getattr(server, "begin_draining")
            if not begin_draining():
                return
            shutdown_thread = Thread(
                target=getattr(server, "shutdown"),
                name=f"signal-{signum}-shutdown",
                daemon=True,
            )
            shutdown_thread.start()

        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, request_shutdown)

    try:
        return serve(
            settings,
            control,
            control.metrics,
            ready_callback=ready,
            shutdown_timeout_seconds=settings.shutdown_grace_seconds,
            cancellation_timeout_seconds=settings.shutdown_cancel_seconds,
        )
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if shutdown_thread is not None:
            shutdown_thread.join(timeout=1)


def command_serve(_: argparse.Namespace) -> int:
    settings = Settings.from_env()
    configure_logging(settings.log_level, settings.log_format)
    try:
        with _exclusive_service_lock(settings.data_dir):
            control, store = build_runtime(settings)
            try:
                recovery = store.reconcile_startup()
                LOGGER.info(
                    "startup recovery completed", extra={"recovery": recovery}
                )
                try:
                    drained = _serve_with_signal_drain(settings, control)
                except KeyboardInterrupt:
                    control.begin_draining()
                    drained = True
            finally:
                store.close()
    except ServiceAlreadyRunningError:
        LOGGER.error("service startup refused: data directory is already in use")
        return 1
    return 0 if drained else 1


def command_doctor(_: argparse.Namespace) -> int:
    settings = Settings.from_env()
    control, store = build_runtime(settings)
    try:
        scenario = default_scenario()
        result = PUCTSearch(
            scenario, default_benchmark(scenario), PolicyValueModel(), seed=7
        ).run(64)
        report = {
            "settings": {
                "data_dir": str(settings.data_dir),
                "database": str(settings.database_path),
                "auth_required": settings.require_auth,
                "allowed_commands": len(settings.allowed_commands),
                "allowed_cwd_roots": len(settings.allowed_cwd_roots),
            },
            "health": control.health(),
            "readiness": control.readiness(),
            "store_integrity": list(store.integrity_check()),
            "engine_probe": {
                "feasible": result.score.feasible,
                "reward": result.score.reward,
                "trajectory": [move.id for move in result.trajectory],
            },
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["readiness"]["ready"] else 1
    finally:
        store.close()


def command_backup(args: argparse.Namespace) -> int:
    settings = BackupSettings.from_env()
    keys, active = load_keyring(settings.backup_keys_file)
    store = SQLiteStore(settings.database_path)
    try:
        path = create_bundle(
            store,
            settings.data_dir / "artifacts",
            args.output,
            keys,
            active,
        )
        print(json.dumps({"backup": str(path), "format": "agent-tree-rl-backup/v1"}))
    finally:
        store.close()
    return 0


def command_restore(args: argparse.Namespace) -> int:
    settings = BackupSettings.from_env()
    keys, _ = load_keyring(settings.backup_keys_file)
    result = restore_bundle(
        args.input,
        settings.database_path,
        settings.data_dir / "artifacts",
        keys,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def command_keyring_check(_: argparse.Namespace) -> int:
    settings = Settings.from_env()
    keys, active = load_keyring(settings.receipt_keys_file)
    print(json.dumps({"active_key_id": active, "key_ids": sorted(keys), "count": len(keys)}))
    return 0


def command_keyring_rotate(_: argparse.Namespace) -> int:
    settings = Settings.from_env()
    key_id = rotate_keyring(settings.receipt_keys_file)
    print(json.dumps({"active_key_id": key_id, "restart_required": True}))
    return 0


def command_backup_keyring_check(_: argparse.Namespace) -> int:
    settings = BackupSettings.from_env()
    keys, active = load_keyring(settings.backup_keys_file)
    print(json.dumps({"active_key_id": active, "key_ids": sorted(keys), "count": len(keys)}))
    return 0


def command_backup_keyring_rotate(_: argparse.Namespace) -> int:
    settings = BackupSettings.from_env()
    key_id = rotate_keyring(settings.backup_keys_file)
    print(json.dumps({"active_key_id": key_id, "restart_required": False}))
    return 0


def command_verify(_: argparse.Namespace) -> int:
    from .verify import main as verify_main

    return verify_main()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="agent-tree-rl")
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    demo = commands.add_parser(
        "demo", help="run the deterministic synthetic decision-tree example"
    )
    demo.add_argument("--simulations", type=_positive_int, default=64)
    demo.add_argument("--seed", type=_nonnegative_int, default=7)
    demo.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    demo.set_defaults(handler=command_demo)
    init = commands.add_parser("init", help="create local key/token/benchmark files")
    init.add_argument("--data-dir", required=True)
    init.add_argument("--tenant", default="default")
    init.add_argument(
        "--token-output",
        help="0600 file for one-time plaintext tokens (default: DATA_DIR/bootstrap-tokens.json)",
    )
    init.set_defaults(handler=command_init)
    serve_command = commands.add_parser("serve", help="run the HTTP control plane")
    serve_command.set_defaults(handler=command_serve)
    doctor = commands.add_parser("doctor", help="check config, storage and engine")
    doctor.set_defaults(handler=command_doctor)
    backup = commands.add_parser("backup", help="create an authenticated state bundle")
    backup.add_argument("--output", required=True)
    backup.set_defaults(handler=command_backup)
    restore = commands.add_parser("restore", help="restore a bundle into empty state")
    restore.add_argument("--input", required=True)
    restore.set_defaults(handler=command_restore)
    keyring = commands.add_parser("keyring", help="inspect or rotate receipt keys")
    key_commands = keyring.add_subparsers(dest="key_command", required=True)
    check = key_commands.add_parser("check")
    check.set_defaults(handler=command_keyring_check)
    rotate = key_commands.add_parser("rotate")
    rotate.set_defaults(handler=command_keyring_rotate)
    backup_keyring = commands.add_parser(
        "backup-keyring", help="inspect or rotate backup authentication keys"
    )
    backup_key_commands = backup_keyring.add_subparsers(
        dest="backup_key_command", required=True
    )
    backup_check = backup_key_commands.add_parser("check")
    backup_check.set_defaults(handler=command_backup_keyring_check)
    backup_rotate = backup_key_commands.add_parser("rotate")
    backup_rotate.set_defaults(handler=command_backup_keyring_rotate)
    verify = commands.add_parser("verify", help="run the controller acceptance proof")
    verify.set_defaults(handler=command_verify)
    verify_compat = commands.add_parser(
        "verify-production",
        help="compatibility alias for 'verify'",
    )
    verify_compat.set_defaults(handler=command_verify)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
