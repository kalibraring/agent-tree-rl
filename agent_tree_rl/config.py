"""Fail-closed environment and secret-file configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Mapping


MAX_PRIVATE_JSON_BYTES = 1024 * 1024


class ConfigurationError(ValueError):
    pass


def _absolute_without_resolving(path: Path) -> Path:
    """Return an absolute lexical path without following a secret-file symlink."""

    return Path(os.path.abspath(os.fspath(path)))


def _validate_private_file(
    metadata: os.stat_result,
    path: Path,
    *,
    require_private: bool,
) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise ConfigurationError(f"secret/config file must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError(f"configuration path is not a regular file: {path}")
    if require_private and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigurationError(f"secret file must not be group/world accessible: {path}")


def _secure_json(
    path: Path,
    *,
    require_private: bool = True,
    max_bytes: int = MAX_PRIVATE_JSON_BYTES,
) -> object:
    """Read bounded JSON from one validated regular-file descriptor.

    Validation happens both before and after ``open``. The descriptor inode is
    compared with the ``lstat`` result so a path replacement cannot separate the
    file that was checked from the file that is read.
    """

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    candidate = Path(path)
    try:
        before = os.lstat(candidate)
    except OSError as error:
        raise ConfigurationError(
            f"required secret/config file cannot be inspected: {candidate}"
        ) from error
    _validate_private_file(before, candidate, require_private=require_private)
    if before.st_size > max_bytes:
        raise ConfigurationError(
            f"secret/config file exceeds {max_bytes} byte limit: {candidate}"
        )

    flags = os.O_RDONLY
    for optional_flag in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= int(getattr(os, optional_flag, 0))
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise ConfigurationError(
            f"required secret/config file cannot be opened securely: {candidate}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ConfigurationError(
                f"secret/config file changed while opening: {candidate}"
            )
        _validate_private_file(opened, candidate, require_private=require_private)
        if opened.st_size > max_bytes:
            raise ConfigurationError(
                f"secret/config file exceeds {max_bytes} byte limit: {candidate}"
            )

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise ConfigurationError(
                f"secret/config file exceeds {max_bytes} byte limit: {candidate}"
            )
    except OSError as error:
        raise ConfigurationError(
            f"required secret/config file cannot be read securely: {candidate}"
        ) from error
    finally:
        os.close(descriptor)

    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"invalid JSON in {candidate}") from error


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    roles: frozenset[str]
    subject_id: str = "unknown"

    def allows(self, *roles: str) -> bool:
        return bool(self.roles.intersection(roles))


@dataclass(frozen=True)
class BackupSettings:
    """Storage-only settings; backup operations never load service secrets."""

    data_dir: Path
    database_path: Path
    backup_keys_file: Path

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "BackupSettings":
        env = dict(os.environ if environ is None else environ)
        data_dir = Path(env.get("AGENT_TREE_RL_DATA_DIR", "/data")).resolve()
        database_path = Path(
            env.get("AGENT_TREE_RL_DATABASE", str(data_dir / "agent-tree-rl.sqlite3"))
        ).resolve()
        keys_file = _absolute_without_resolving(
            Path(
                env.get(
                    "AGENT_TREE_RL_BACKUP_KEYS_FILE",
                    str(data_dir / "backup-keys.json"),
                )
            )
        )
        if data_dir not in database_path.parents and database_path.parent != data_dir:
            raise ConfigurationError(
                f"database path escapes persistent data directory: {database_path}"
            )
        return cls(data_dir, database_path, keys_file)


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    data_dir: Path
    database_path: Path
    receipt_keys_file: Path
    admin_token_file: Path
    benchmark_dir: Path
    benchmark_file: Path | None = None
    benchmark_signing_key_file: Path | None = None
    require_auth: bool = True
    log_format: str = "json"
    log_level: str = "INFO"
    max_request_bytes: int = 1_048_576
    max_workers: int = 8
    max_operational_workers: int = 2
    shutdown_grace_seconds: int = 30
    shutdown_cancel_seconds: int = 5
    default_tenant_budget: int = 10_000
    lease_seconds: int = 60
    benchmark_receipt_max_age_seconds: int = 300
    minimum_hidden_benchmark_score_ppm: int = 900_000
    hidden_benchmark_attempt_limit: int = 3
    hidden_benchmark_quota_window_seconds: int = 300
    require_separation_of_duties: bool = True
    allow_sample_benchmark: bool = False
    allowed_commands: tuple[str, ...] = ()
    allowed_cwd_roots: tuple[Path, ...] = ()
    token_digests: Mapping[str, Principal] = field(default_factory=dict)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = dict(os.environ if environ is None else environ)
        data_dir = Path(env.get("AGENT_TREE_RL_DATA_DIR", "/data")).resolve()
        host = env.get("AGENT_TREE_RL_HOST", "127.0.0.1")
        port = _bounded_int(env, "AGENT_TREE_RL_PORT", 8080, 1, 65535)
        require_auth = _boolean(env, "AGENT_TREE_RL_REQUIRE_AUTH", True)
        keys_file = _absolute_without_resolving(
            Path(
                env.get(
                    "AGENT_TREE_RL_RECEIPT_KEYS_FILE",
                    str(data_dir / "receipt-keys.json"),
                )
            )
        )
        token_file = _absolute_without_resolving(
            Path(
                env.get(
                    "AGENT_TREE_RL_ADMIN_TOKEN_FILE",
                    str(data_dir / "api-tokens.json"),
                )
            )
        )
        benchmark_dir = Path(
            env.get("AGENT_TREE_RL_BENCHMARK_DIR", str(data_dir / "benchmarks"))
        ).resolve()
        benchmark_file = _absolute_without_resolving(
            Path(
                env.get(
                    "AGENT_TREE_RL_BENCHMARK_FILE",
                    str(benchmark_dir / "policy.json"),
                )
            )
        )
        benchmark_signing_key_file = _absolute_without_resolving(
            Path(
                env.get(
                    "AGENT_TREE_RL_BENCHMARK_SIGNING_KEY_FILE",
                    str(data_dir / "benchmark-signing.key"),
                )
            )
        )
        database_path = Path(
            env.get("AGENT_TREE_RL_DATABASE", str(data_dir / "agent-tree-rl.sqlite3"))
        ).resolve()

        token_digests: dict[str, Principal] = {}
        if require_auth:
            raw_tokens = _secure_json(token_file)
            if not isinstance(raw_tokens, dict) or not raw_tokens:
                raise ConfigurationError("API token file must contain at least one digest")
            for digest, value in raw_tokens.items():
                if (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or not isinstance(value, dict)
                ):
                    raise ConfigurationError("API token entries must use SHA-256 digest keys")
                tenant = value.get("tenant_id")
                roles = value.get("roles")
                subject = value.get("subject_id")
                if (
                    not isinstance(tenant, str)
                    or not tenant
                    or not isinstance(roles, list)
                    or not isinstance(subject, str)
                    or not subject
                ):
                    raise ConfigurationError("API token principal is invalid")
                role_set = frozenset(str(role) for role in roles)
                if not role_set or not role_set.issubset(
                    {"agent", "operator", "promoter", "auditor"}
                ):
                    raise ConfigurationError("API token roles are invalid")
                token_digests[digest] = Principal(tenant, role_set, subject)

        commands = tuple(
            item for item in env.get("AGENT_TREE_RL_ALLOWED_COMMANDS", "").split(":") if item
        )
        roots = tuple(
            Path(item).resolve()
            for item in env.get("AGENT_TREE_RL_ALLOWED_CWD_ROOTS", str(data_dir)).split(":")
            if item
        )
        settings = cls(
            host=host,
            port=port,
            data_dir=data_dir,
            database_path=database_path,
            receipt_keys_file=keys_file,
            admin_token_file=token_file,
            benchmark_dir=benchmark_dir,
            benchmark_file=benchmark_file,
            benchmark_signing_key_file=benchmark_signing_key_file,
            require_auth=require_auth,
            log_format=env.get("AGENT_TREE_RL_LOG_FORMAT", "json"),
            log_level=env.get("AGENT_TREE_RL_LOG_LEVEL", "INFO").upper(),
            max_request_bytes=_bounded_int(
                env, "AGENT_TREE_RL_MAX_REQUEST_BYTES", 1_048_576, 1_024, 16_777_216
            ),
            max_workers=_bounded_int(env, "AGENT_TREE_RL_MAX_WORKERS", 8, 1, 64),
            max_operational_workers=_bounded_int(
                env, "AGENT_TREE_RL_MAX_OPERATIONAL_WORKERS", 2, 1, 8
            ),
            shutdown_grace_seconds=_bounded_int(
                env, "AGENT_TREE_RL_SHUTDOWN_GRACE_SECONDS", 30, 1, 300
            ),
            shutdown_cancel_seconds=_bounded_int(
                env, "AGENT_TREE_RL_SHUTDOWN_CANCEL_SECONDS", 5, 1, 30
            ),
            default_tenant_budget=_bounded_int(
                env, "AGENT_TREE_RL_DEFAULT_TENANT_BUDGET", 10_000, 1, 10**9
            ),
            lease_seconds=_bounded_int(env, "AGENT_TREE_RL_LEASE_SECONDS", 60, 5, 3600),
            benchmark_receipt_max_age_seconds=_bounded_int(
                env,
                "AGENT_TREE_RL_BENCHMARK_RECEIPT_MAX_AGE_SECONDS",
                300,
                60,
                86_400,
            ),
            minimum_hidden_benchmark_score_ppm=_bounded_int(
                env,
                "AGENT_TREE_RL_MINIMUM_HIDDEN_BENCHMARK_SCORE_PPM",
                900_000,
                0,
                1_000_000,
            ),
            hidden_benchmark_attempt_limit=_bounded_int(
                env, "AGENT_TREE_RL_HIDDEN_BENCHMARK_ATTEMPT_LIMIT", 3, 1, 100
            ),
            hidden_benchmark_quota_window_seconds=_bounded_int(
                env,
                "AGENT_TREE_RL_HIDDEN_BENCHMARK_QUOTA_WINDOW_SECONDS",
                300,
                60,
                86_400,
            ),
            require_separation_of_duties=_boolean(
                env, "AGENT_TREE_RL_REQUIRE_SEPARATION_OF_DUTIES", True
            ),
            allow_sample_benchmark=_boolean(
                env, "AGENT_TREE_RL_ALLOW_SAMPLE_BENCHMARK", False
            ),
            allowed_commands=commands,
            allowed_cwd_roots=roots,
            token_digests=token_digests,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.host not in {"127.0.0.1", "::1", "0.0.0.0"}:
            raise ConfigurationError("host must be an explicit local/all-interface address")
        if self.log_format not in {"json", "text"}:
            raise ConfigurationError("log format must be json or text")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ConfigurationError("unsupported log level")
        if not self.require_auth and self.host not in {"127.0.0.1", "::1"}:
            raise ConfigurationError(
                "authentication may be disabled only on a loopback listener"
            )
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        if not self.data_dir.is_dir():
            raise ConfigurationError("data directory is not a directory")
        if (
            self.data_dir not in self.database_path.parents
            and self.database_path.parent != self.data_dir
        ):
            raise ConfigurationError(
                f"database path escapes persistent data directory: {self.database_path}"
            )
        forbidden_evidence_commands = {
            "sh", "bash", "zsh", "fish", "dash", "env",
            "python", "python3", "node", "ruby", "perl", "php",
            "npm", "npx", "pip", "pip3", "curl", "wget",
        }
        for command in self.allowed_commands:
            candidate = Path(command).expanduser()
            if not candidate.is_absolute():
                raise ConfigurationError(
                    "evidence commands must use exact absolute paths"
                )
            try:
                configured = os.lstat(candidate)
                target = candidate.resolve(strict=True)
            except OSError as error:
                raise ConfigurationError(
                    f"evidence command cannot be inspected: {candidate}"
                ) from error
            if stat.S_ISLNK(configured.st_mode):
                raise ConfigurationError(
                    f"evidence command must not be a symlink: {candidate}"
                )
            names = {candidate.name.lower(), target.name.lower()}
            forbidden = sorted(
                name
                for name in names
                if name in forbidden_evidence_commands or name.startswith("python3.")
            )
            if forbidden:
                raise ConfigurationError(
                    "general interpreter/network tool forbidden as evidence command: "
                    + ", ".join(forbidden)
                )

    def authenticate(self, bearer_token: str) -> Principal | None:
        digest = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()
        # The digest itself is non-secret, but compare all candidates without early exit.
        match: Principal | None = None
        import hmac

        for expected, principal in self.token_digests.items():
            if hmac.compare_digest(expected, digest):
                match = principal
        return match


def _boolean(env: Mapping[str, str], name: str, default: bool) -> bool:
    value = env.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean")


def _bounded_int(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    try:
        value = int(env.get(name, str(default)))
    except ValueError as error:
        raise ConfigurationError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be in [{minimum}, {maximum}]")
    return value
