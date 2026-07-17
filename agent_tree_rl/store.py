"""SQLite persistence for the production Agent Tree RL control plane.

The store provides small, transactional primitives rather than embedding
orchestration policy.  All public identifiers are tenant scoped.  Decision
events, signed receipts, policy artifacts, and promotion decisions are made
append-only with SQLite triggers so accidental mutation fails closed.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any, Callable
import uuid

from .crypto import (
    JSONValue,
    ReceiptVerifier,
    ReplayDetectedError,
    canonical_json_bytes,
    sha256_hex,
)


SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class StoreError(RuntimeError):
    """Base class for persistence-domain failures."""


class StoreConfigurationError(StoreError):
    """The store is missing a required production dependency."""


class ConflictError(StoreError):
    """A compare-and-swap or immutable identity constraint failed."""


class NotFoundError(StoreError):
    """A requested tenant-scoped resource does not exist."""


class LeaseUnavailableError(ConflictError):
    """A live lease is held by another worker."""


class BudgetExceededError(ConflictError):
    """A reservation would exceed the externally configured budget."""


@dataclass(frozen=True)
class IdempotencyRecord:
    tenant_id: str
    scope: str
    key: str
    request_hash: str
    status: str
    result: JSONValue | None
    created_at: int
    updated_at: int
    expires_at: int | None
    is_new: bool = False


@dataclass(frozen=True)
class Lease:
    tenant_id: str
    resource_id: str
    holder_id: str | None
    fencing_token: int
    acquired_at: int
    heartbeat_at: int
    expires_at: int


@dataclass(frozen=True)
class BudgetSnapshot:
    tenant_id: str
    budget_id: str
    limit_units: int
    reserved_units: int
    consumed_units: int
    available_units: int
    version: int


@dataclass(frozen=True)
class Promotion:
    audit_id: str
    tenant_id: str
    policy_name: str
    artifact_id: str
    previous_artifact_id: str | None
    generation: int
    decided_by: str
    reason: str
    benchmark_receipt_id: str | None
    promoted_at: int


@dataclass(frozen=True)
class TrainingRun:
    tenant_id: str
    training_id: str
    policy_name: str
    artifact_id: str
    trained_by: str
    lease_fencing_token: int
    report: JSONValue
    created_at: int


_MIGRATION_1 = (
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        stream_id TEXT NOT NULL,
        stream_version INTEGER NOT NULL CHECK (stream_version > 0),
        event_type TEXT NOT NULL,
        occurred_at INTEGER NOT NULL,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        UNIQUE (tenant_id, event_id),
        UNIQUE (tenant_id, stream_id, stream_version)
    )
    """,
    "CREATE INDEX events_tenant_sequence ON events (tenant_id, sequence)",
    "CREATE INDEX events_tenant_stream ON events (tenant_id, stream_id, stream_version)",
    """
    CREATE TABLE receipt_nonces (
        tenant_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at INTEGER,
        consumed_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, purpose, nonce)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX receipt_nonces_expiry ON receipt_nonces (expires_at)",
    """
    CREATE TABLE evidence_receipts (
        tenant_id TEXT NOT NULL,
        receipt_id TEXT NOT NULL,
        evidence_kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        artifact_uri TEXT,
        content_sha256 TEXT,
        signer_key_id TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER,
        envelope_json TEXT NOT NULL,
        recorded_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, receipt_id)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX evidence_subject ON evidence_receipts (tenant_id, subject_id)",
    """
    CREATE TABLE experience_receipts (
        tenant_id TEXT NOT NULL,
        receipt_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        episode_id TEXT NOT NULL,
        trajectory_hash TEXT NOT NULL,
        reward REAL NOT NULL,
        signer_key_id TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER,
        payload_json TEXT NOT NULL,
        envelope_json TEXT NOT NULL,
        recorded_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, receipt_id),
        UNIQUE (tenant_id, run_id, episode_id)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX experience_run ON experience_receipts (tenant_id, run_id, recorded_at)",
    """
    CREATE TABLE idempotency_records (
        tenant_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('IN_PROGRESS', 'COMPLETED', 'FAILED')),
        result_json TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        PRIMARY KEY (tenant_id, scope, idempotency_key)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX idempotency_expiry ON idempotency_records (expires_at)",
    """
    CREATE TABLE leases (
        tenant_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        holder_id TEXT,
        fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
        acquired_at INTEGER NOT NULL,
        heartbeat_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, resource_id)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX leases_expiry ON leases (expires_at)",
    """
    CREATE TABLE budgets (
        tenant_id TEXT NOT NULL,
        budget_id TEXT NOT NULL,
        limit_units INTEGER NOT NULL CHECK (limit_units >= 0),
        reserved_units INTEGER NOT NULL DEFAULT 0 CHECK (reserved_units >= 0),
        consumed_units INTEGER NOT NULL DEFAULT 0 CHECK (consumed_units >= 0),
        version INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, budget_id),
        CHECK (reserved_units + consumed_units <= limit_units)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE budget_reservations (
        tenant_id TEXT NOT NULL,
        budget_id TEXT NOT NULL,
        reservation_id TEXT NOT NULL,
        units INTEGER NOT NULL CHECK (units > 0),
        status TEXT NOT NULL CHECK (status IN ('RESERVED', 'CONSUMED', 'RELEASED')),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, budget_id, reservation_id),
        FOREIGN KEY (tenant_id, budget_id)
            REFERENCES budgets (tenant_id, budget_id)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE policy_artifacts (
        tenant_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        version TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        artifact_uri TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        registered_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, artifact_id),
        UNIQUE (tenant_id, policy_name, version)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX policy_artifacts_name ON policy_artifacts (tenant_id, policy_name, registered_at)",
    """
    CREATE TABLE training_runs (
        tenant_id TEXT NOT NULL,
        training_id TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        trained_by TEXT NOT NULL,
        lease_fencing_token INTEGER NOT NULL CHECK (lease_fencing_token > 0),
        report_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, training_id),
        FOREIGN KEY (tenant_id, artifact_id)
            REFERENCES policy_artifacts (tenant_id, artifact_id)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX training_artifact ON training_runs (tenant_id, artifact_id, created_at)",
    """
    CREATE TABLE champion_registry (
        tenant_id TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        generation INTEGER NOT NULL CHECK (generation > 0),
        promoted_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, policy_name),
        FOREIGN KEY (tenant_id, artifact_id)
            REFERENCES policy_artifacts (tenant_id, artifact_id)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE promotion_audit (
        audit_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        previous_artifact_id TEXT,
        generation INTEGER NOT NULL,
        decided_by TEXT NOT NULL,
        reason TEXT NOT NULL,
        benchmark_receipt_id TEXT,
        promoted_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, audit_id),
        UNIQUE (tenant_id, policy_name, generation),
        FOREIGN KEY (tenant_id, artifact_id)
            REFERENCES policy_artifacts (tenant_id, artifact_id)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX promotion_policy ON promotion_audit (tenant_id, policy_name, generation)",
    """
    CREATE TRIGGER events_no_update BEFORE UPDATE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END
    """,
    """
    CREATE TRIGGER events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END
    """,
    """
    CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence_receipts
    BEGIN SELECT RAISE(ABORT, 'evidence receipts are append-only'); END
    """,
    """
    CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence_receipts
    BEGIN SELECT RAISE(ABORT, 'evidence receipts are append-only'); END
    """,
    """
    CREATE TRIGGER experience_no_update BEFORE UPDATE ON experience_receipts
    BEGIN SELECT RAISE(ABORT, 'experience receipts are append-only'); END
    """,
    """
    CREATE TRIGGER experience_no_delete BEFORE DELETE ON experience_receipts
    BEGIN SELECT RAISE(ABORT, 'experience receipts are append-only'); END
    """,
    """
    CREATE TRIGGER artifacts_no_update BEFORE UPDATE ON policy_artifacts
    BEGIN SELECT RAISE(ABORT, 'policy artifacts are immutable'); END
    """,
    """
    CREATE TRIGGER artifacts_no_delete BEFORE DELETE ON policy_artifacts
    BEGIN SELECT RAISE(ABORT, 'policy artifacts are immutable'); END
    """,
    """
    CREATE TRIGGER training_no_update BEFORE UPDATE ON training_runs
    BEGIN SELECT RAISE(ABORT, 'training runs are append-only'); END
    """,
    """
    CREATE TRIGGER training_no_delete BEFORE DELETE ON training_runs
    BEGIN SELECT RAISE(ABORT, 'training runs are append-only'); END
    """,
    """
    CREATE TRIGGER promotion_no_update BEFORE UPDATE ON promotion_audit
    BEGIN SELECT RAISE(ABORT, 'promotion audit is append-only'); END
    """,
    """
    CREATE TRIGGER promotion_no_delete BEFORE DELETE ON promotion_audit
    BEGIN SELECT RAISE(ABORT, 'promotion audit is append-only'); END
    """,
)
_MIGRATIONS: dict[int, tuple[str, ...]] = {1: _MIGRATION_1}


class SQLiteStore:
    """Tenant-scoped SQLite state with WAL, migrations, and atomic primitives."""

    def __init__(
        self,
        path: str | Path,
        *,
        receipt_verifier: ReceiptVerifier | None = None,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = 5.0,
        replay_grace_seconds: int = 300,
    ) -> None:
        if replay_grace_seconds < 0:
            raise ValueError("replay_grace_seconds must be nonnegative")
        raw_path = str(path)
        self.path = (
            ":memory:"
            if raw_path == ":memory:"
            else str(Path(raw_path).expanduser().resolve())
        )
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._receipt_verifier = receipt_verifier
        self._replay_grace_seconds = replay_grace_seconds
        self._lock = threading.RLock()
        self._local = threading.local()
        self._connection = sqlite3.connect(
            self.path,
            timeout=timeout_seconds,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute(f"PRAGMA busy_timeout = {int(timeout_seconds * 1000)}")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._journal_mode = str(
            self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        ).lower()
        self._apply_migrations()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None  # type: ignore[assignment]

    def reconcile_startup(self) -> dict[str, int]:
        """Atomically recover state owned by a terminated service instance.

        The caller must hold the service's exclusive runtime lock. Under that
        precondition every ``IN_PROGRESS`` record, ``RESERVED`` budget row, and
        held lease belongs to a process that can no longer commit. Completed
        operations are never changed: their state effect, budget consumption,
        and idempotency result are committed in one SQLite transaction.

        Interrupted idempotency keys are finalized as non-retryable failures.
        This is deliberately fail closed because an external evidence command
        may have produced an effect before the process died. An operator can
        investigate and submit a new key without losing reserved capacity.
        """

        now = self._now()
        interrupted = _json_text(
            {
                "error_type": "InterruptedOperation",
                "retry_safe": False,
            }
        )
        with self.transaction() as connection:
            # Do not repair through an unexplained accounting mismatch. A
            # mismatch can otherwise turn recovery into an under-count and
            # permit a later double spend.
            accounting = connection.execute(
                "SELECT b.tenant_id,b.budget_id,b.reserved_units,b.consumed_units,"
                "COALESCE(SUM(CASE WHEN r.status='RESERVED' THEN r.units ELSE 0 END),0) "
                "AS calculated_reserved,"
                "COALESCE(SUM(CASE WHEN r.status='CONSUMED' THEN r.units ELSE 0 END),0) "
                "AS calculated_consumed "
                "FROM budgets b LEFT JOIN budget_reservations r "
                "ON r.tenant_id=b.tenant_id AND r.budget_id=b.budget_id "
                "GROUP BY b.tenant_id,b.budget_id"
            ).fetchall()
            for row in accounting:
                if (
                    int(row["reserved_units"]) != int(row["calculated_reserved"])
                    or int(row["consumed_units"])
                    != int(row["calculated_consumed"])
                ):
                    raise StoreError(
                        "budget accounting mismatch; startup recovery aborted"
                    )

            reservation_totals = connection.execute(
                "SELECT COUNT(*) AS reservation_count,COALESCE(SUM(units),0) AS units "
                "FROM budget_reservations WHERE status='RESERVED'"
            ).fetchone()
            released_reservations = int(reservation_totals["reservation_count"])
            released_units = int(reservation_totals["units"])

            idempotency_cursor = connection.execute(
                "UPDATE idempotency_records SET status='FAILED',result_json=?,updated_at=?,"
                "expires_at=NULL "
                "WHERE status='IN_PROGRESS'",
                (interrupted, now),
            )
            failed_idempotency = int(idempotency_cursor.rowcount)

            if released_reservations:
                connection.execute(
                    "UPDATE budget_reservations SET status='RELEASED',updated_at=? "
                    "WHERE status='RESERVED'",
                    (now,),
                )
                connection.execute(
                    "UPDATE budgets SET reserved_units=0,version=version+1,updated_at=? "
                    "WHERE reserved_units>0",
                    (now,),
                )

            # The exclusive runtime lock proves these holders belong to a dead
            # service instance even if their wall-clock TTL has not elapsed.
            # Keep the fencing token so a future acquisition increments it.
            lease_cursor = connection.execute(
                "UPDATE leases SET holder_id=NULL,heartbeat_at=?,expires_at=? "
                "WHERE holder_id IS NOT NULL",
                (now, now),
            )
            released_leases = int(lease_cursor.rowcount)

        return {
            "failed_idempotency_records": failed_idempotency,
            "released_budget_reservations": released_reservations,
            "released_budget_units": released_units,
            "released_leases": released_leases,
        }

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        """Open an atomic transaction; nested callers use savepoints."""

        with self._lock:
            depth = getattr(self._local, "transaction_depth", 0)
            savepoint = f"nested_{depth}"
            if depth == 0:
                self._connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            else:
                self._connection.execute(f"SAVEPOINT {savepoint}")
            self._local.transaction_depth = depth + 1
            try:
                yield self._connection
            except BaseException:
                if depth == 0:
                    self._connection.execute("ROLLBACK")
                else:
                    self._connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            else:
                if depth == 0:
                    self._connection.execute("COMMIT")
                else:
                    self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            finally:
                self._local.transaction_depth = depth

    def _apply_migrations(self) -> None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations "
                    "(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)"
                )
                row = self._connection.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
                ).fetchone()
                current = int(row[0])
                if current > SCHEMA_VERSION:
                    raise StoreConfigurationError(
                        f"database schema {current} is newer than supported {SCHEMA_VERSION}"
                    )
                for version in range(current + 1, SCHEMA_VERSION + 1):
                    for statement in _MIGRATIONS[version]:
                        self._connection.execute(statement)
                    self._connection.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                        (version, self._now()),
                    )
                    self._connection.execute(f"PRAGMA user_version = {version}")
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def schema_version(self) -> int:
        row = self._fetchone("PRAGMA user_version")
        if row is None:
            raise StoreError("SQLite did not return a schema version")
        return int(row[0])

    def _fetchone(
        self, sql: str, parameters: tuple[Any, ...] | list[Any] = ()
    ) -> sqlite3.Row | None:
        # Reads share the transaction connection. Lock them so another request
        # cannot observe this connection's uncommitted writes.
        with self._lock:
            return self._connection.execute(sql, parameters).fetchone()

    def _fetchall(
        self, sql: str, parameters: tuple[Any, ...] | list[Any] = ()
    ) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._connection.execute(sql, parameters).fetchall())

    def append_event(
        self,
        tenant_id: str,
        stream_id: str,
        event_type: str,
        payload: JSONValue,
        *,
        event_id: str | None = None,
        expected_stream_version: int | None = None,
        occurred_at: int | None = None,
    ) -> dict[str, Any]:
        _required(tenant_id=tenant_id, stream_id=stream_id, event_type=event_type)
        payload_json = _json_text(payload)
        event_id = event_id or uuid.uuid4().hex
        now = self._timestamp(occurred_at)
        with self.transaction() as connection:
            current = int(
                connection.execute(
                    "SELECT COALESCE(MAX(stream_version), 0) FROM events "
                    "WHERE tenant_id = ? AND stream_id = ?",
                    (tenant_id, stream_id),
                ).fetchone()[0]
            )
            if expected_stream_version is not None and current != expected_stream_version:
                raise ConflictError(
                    f"stream version is {current}, expected {expected_stream_version}"
                )
            version = current + 1
            try:
                cursor = connection.execute(
                    "INSERT INTO events(tenant_id,event_id,stream_id,stream_version,"
                    "event_type,occurred_at,payload_json,payload_sha256) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        tenant_id,
                        event_id,
                        stream_id,
                        version,
                        event_type,
                        now,
                        payload_json,
                        sha256_hex(payload),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("event identity or stream version already exists") from exc
            sequence = int(cursor.lastrowid)
        return {
            "sequence": sequence,
            "tenant_id": tenant_id,
            "event_id": event_id,
            "stream_id": stream_id,
            "stream_version": version,
            "event_type": event_type,
            "occurred_at": now,
            "payload": json.loads(payload_json),
            "payload_sha256": sha256_hex(payload),
        }

    def list_events(
        self,
        tenant_id: str,
        *,
        stream_id: str | None = None,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        _required(tenant_id=tenant_id)
        _positive_limit(limit)
        sql = "SELECT * FROM events WHERE tenant_id = ? AND sequence > ?"
        parameters: list[Any] = [tenant_id, after_sequence]
        if stream_id is not None:
            sql += " AND stream_id = ?"
            parameters.append(stream_id)
        sql += " ORDER BY sequence LIMIT ?"
        parameters.append(limit)
        rows = self._fetchall(sql, parameters)
        return [_event_dict(row) for row in rows]

    def claim_replay_nonce(
        self, tenant_id: str, purpose: str, nonce: str, expires_at: int | None
    ) -> bool:
        _required(tenant_id=tenant_id, purpose=purpose, nonce=nonce)
        now = self._now()
        retained_until = (
            None if expires_at is None else expires_at + self._replay_grace_seconds
        )
        with self.transaction() as connection:
            connection.execute(
                "DELETE FROM receipt_nonces WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            try:
                connection.execute(
                    "INSERT INTO receipt_nonces(tenant_id,purpose,nonce,expires_at,consumed_at) "
                    "VALUES (?,?,?,?,?)",
                    (tenant_id, purpose, nonce, retained_until, now),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def prune_replay_nonces(self, *, before: int | None = None) -> int:
        cutoff = self._timestamp(before)
        with self.transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM receipt_nonces WHERE expires_at IS NOT NULL AND expires_at < ?",
                (cutoff,),
            )
            return int(cursor.rowcount)

    def record_evidence_receipt(
        self,
        tenant_id: str,
        envelope: Mapping[str, Any],
        *,
        receipt_id: str | None = None,
    ) -> dict[str, Any]:
        # Detach mutable caller input before the authenticate/validate/store path.
        envelope = json.loads(_json_text(envelope))
        payload = self._verify_receipt(tenant_id, "evidence", envelope)
        if not isinstance(payload, dict):
            raise StoreError("evidence receipt payload must be an object")
        evidence_kind = _payload_text(payload, "evidence_kind")
        subject_id = _payload_text(payload, "subject_id")
        artifact_uri = _optional_payload_text(payload, "artifact_uri")
        content_sha256 = _optional_payload_text(payload, "content_sha256")
        if content_sha256 is not None:
            _sha256(content_sha256)
        receipt_id = receipt_id or sha256_hex(envelope)
        now = self._now()
        with self.transaction() as connection:
            self._claim_envelope_nonce(envelope)
            try:
                connection.execute(
                    "INSERT INTO evidence_receipts(tenant_id,receipt_id,evidence_kind,"
                    "subject_id,artifact_uri,content_sha256,signer_key_id,issued_at,"
                    "expires_at,envelope_json,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant_id,
                        receipt_id,
                        evidence_kind,
                        subject_id,
                        artifact_uri,
                        content_sha256,
                        envelope["key_id"],
                        envelope["issued_at"],
                        envelope["expires_at"],
                        _json_text(envelope),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("evidence receipt already exists") from exc
        return self.get_evidence_receipt(tenant_id, receipt_id)

    def get_evidence_receipt(self, tenant_id: str, receipt_id: str) -> dict[str, Any]:
        _required(tenant_id=tenant_id, receipt_id=receipt_id)
        row = self._fetchone(
            "SELECT * FROM evidence_receipts WHERE tenant_id = ? AND receipt_id = ?",
            (tenant_id, receipt_id),
        )
        if row is None:
            raise NotFoundError("evidence receipt not found")
        result = dict(row)
        result["envelope"] = json.loads(result.pop("envelope_json"))
        return result

    def record_experience_receipt(
        self,
        tenant_id: str,
        envelope: Mapping[str, Any],
        *,
        receipt_id: str | None = None,
    ) -> dict[str, Any]:
        envelope = json.loads(_json_text(envelope))
        payload = self._verify_receipt(tenant_id, "experience", envelope)
        if not isinstance(payload, dict):
            raise StoreError("experience receipt payload must be an object")
        run_id = _payload_text(payload, "run_id")
        episode_id = _payload_text(payload, "episode_id")
        trajectory_hash = _payload_text(payload, "trajectory_hash")
        _sha256(trajectory_hash)
        reward = payload.get("reward")
        if not isinstance(reward, (int, float)) or isinstance(reward, bool):
            raise StoreError("experience reward must be numeric")
        reward = float(reward)
        if not -1.0 <= reward <= 1.0:
            raise StoreError("experience reward must be in [-1, 1]")
        receipt_id = receipt_id or sha256_hex(envelope)
        now = self._now()
        with self.transaction() as connection:
            self._claim_envelope_nonce(envelope)
            try:
                connection.execute(
                    "INSERT INTO experience_receipts(tenant_id,receipt_id,run_id,episode_id,"
                    "trajectory_hash,reward,signer_key_id,issued_at,expires_at,payload_json,"
                    "envelope_json,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant_id,
                        receipt_id,
                        run_id,
                        episode_id,
                        trajectory_hash,
                        reward,
                        envelope["key_id"],
                        envelope["issued_at"],
                        envelope["expires_at"],
                        _json_text(payload),
                        _json_text(envelope),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("experience receipt or episode already exists") from exc
        return self._experience_row(tenant_id, receipt_id)

    def list_experience_receipts(
        self, tenant_id: str, *, run_id: str | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        _required(tenant_id=tenant_id)
        _positive_limit(limit)
        sql = "SELECT * FROM experience_receipts WHERE tenant_id = ?"
        parameters: list[Any] = [tenant_id]
        if run_id is not None:
            sql += " AND run_id = ?"
            parameters.append(run_id)
        sql += " ORDER BY recorded_at, receipt_id LIMIT ?"
        parameters.append(limit)
        return [_experience_dict(row) for row in self._fetchall(sql, parameters)]

    def _experience_row(self, tenant_id: str, receipt_id: str) -> dict[str, Any]:
        row = self._fetchone(
            "SELECT * FROM experience_receipts WHERE tenant_id = ? AND receipt_id = ?",
            (tenant_id, receipt_id),
        )
        if row is None:
            raise NotFoundError("experience receipt not found")
        return _experience_dict(row)

    def _verify_receipt(
        self, tenant_id: str, purpose: str, envelope: Mapping[str, Any]
    ) -> JSONValue:
        _required(tenant_id=tenant_id)
        if self._receipt_verifier is None:
            raise StoreConfigurationError(
                "receipt_verifier is required to persist authenticated receipts"
            )
        return self._receipt_verifier.verify(
            envelope,
            expected_purpose=purpose,
            expected_tenant_id=tenant_id,
            # Persistence claims this nonce inside the receipt insert transaction.
            replay_guard=None,
        )

    def _claim_envelope_nonce(self, envelope: Mapping[str, Any]) -> None:
        if not self.claim_replay_nonce(
            envelope["tenant_id"],
            envelope["purpose"],
            envelope["nonce"],
            envelope["expires_at"],
        ):
            raise ReplayDetectedError("receipt nonce has already been consumed")

    def claim_idempotency(
        self,
        tenant_id: str,
        scope: str,
        key: str,
        request: JSONValue,
        *,
        ttl_seconds: int | None = 86_400,
    ) -> IdempotencyRecord:
        _required(tenant_id=tenant_id, scope=scope, key=key)
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive or None")
        request_hash = sha256_hex(request)
        now = self._now()
        expires_at = None if ttl_seconds is None else now + ttl_seconds
        with self.transaction() as connection:
            connection.execute(
                "DELETE FROM idempotency_records WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            row = connection.execute(
                "SELECT * FROM idempotency_records WHERE tenant_id=? AND scope=? "
                "AND idempotency_key=?",
                (tenant_id, scope, key),
            ).fetchone()
            if row is not None:
                if row["request_hash"] != request_hash:
                    raise ConflictError("idempotency key was used for a different request")
                return _idempotency_record(row, is_new=False)
            connection.execute(
                "INSERT INTO idempotency_records(tenant_id,scope,idempotency_key,request_hash,"
                "status,result_json,created_at,updated_at,expires_at) "
                "VALUES (?,?,?,?, 'IN_PROGRESS', NULL,?,?,?)",
                (tenant_id, scope, key, request_hash, now, now, expires_at),
            )
            row = connection.execute(
                "SELECT * FROM idempotency_records WHERE tenant_id=? AND scope=? "
                "AND idempotency_key=?",
                (tenant_id, scope, key),
            ).fetchone()
            return _idempotency_record(row, is_new=True)

    def complete_idempotency(
        self, tenant_id: str, scope: str, key: str, result: JSONValue
    ) -> IdempotencyRecord:
        return self._finish_idempotency(tenant_id, scope, key, "COMPLETED", result)

    def fail_idempotency(
        self, tenant_id: str, scope: str, key: str, error: JSONValue
    ) -> IdempotencyRecord:
        return self._finish_idempotency(tenant_id, scope, key, "FAILED", error)

    def _finish_idempotency(
        self, tenant_id: str, scope: str, key: str, status: str, result: JSONValue
    ) -> IdempotencyRecord:
        _required(tenant_id=tenant_id, scope=scope, key=key)
        result_json = _json_text(result)
        now = self._now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM idempotency_records WHERE tenant_id=? AND scope=? "
                "AND idempotency_key=?",
                (tenant_id, scope, key),
            ).fetchone()
            if row is None:
                raise NotFoundError("idempotency record not found")
            if row["status"] != "IN_PROGRESS":
                if row["status"] == status and row["result_json"] == result_json:
                    return _idempotency_record(row, is_new=False)
                raise ConflictError("idempotency record is already finalized")
            connection.execute(
                "UPDATE idempotency_records SET status=?,result_json=?,updated_at=? "
                "WHERE tenant_id=? AND scope=? AND idempotency_key=?",
                (status, result_json, now, tenant_id, scope, key),
            )
            row = connection.execute(
                "SELECT * FROM idempotency_records WHERE tenant_id=? AND scope=? "
                "AND idempotency_key=?",
                (tenant_id, scope, key),
            ).fetchone()
            return _idempotency_record(row, is_new=False)

    def acquire_lease(
        self,
        tenant_id: str,
        resource_id: str,
        holder_id: str,
        *,
        ttl_seconds: int,
        now: int | None = None,
    ) -> Lease:
        _required(tenant_id=tenant_id, resource_id=resource_id, holder_id=holder_id)
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        timestamp = self._timestamp(now)
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE tenant_id=? AND resource_id=?",
                (tenant_id, resource_id),
            ).fetchone()
            if row is None:
                token = 1
                acquired_at = timestamp
                connection.execute(
                    "INSERT INTO leases VALUES (?,?,?,?,?,?,?)",
                    (
                        tenant_id,
                        resource_id,
                        holder_id,
                        token,
                        acquired_at,
                        timestamp,
                        timestamp + ttl_seconds,
                    ),
                )
            elif row["holder_id"] == holder_id and row["expires_at"] > timestamp:
                token = int(row["fencing_token"])
                acquired_at = int(row["acquired_at"])
                connection.execute(
                    "UPDATE leases SET heartbeat_at=?,expires_at=? "
                    "WHERE tenant_id=? AND resource_id=?",
                    (timestamp, timestamp + ttl_seconds, tenant_id, resource_id),
                )
            elif row["holder_id"] is None or row["expires_at"] <= timestamp:
                token = int(row["fencing_token"]) + 1
                acquired_at = timestamp
                connection.execute(
                    "UPDATE leases SET holder_id=?,fencing_token=?,acquired_at=?,"
                    "heartbeat_at=?,expires_at=? WHERE tenant_id=? AND resource_id=?",
                    (
                        holder_id,
                        token,
                        acquired_at,
                        timestamp,
                        timestamp + ttl_seconds,
                        tenant_id,
                        resource_id,
                    ),
                )
            else:
                raise LeaseUnavailableError(
                    f"lease is held by {row['holder_id']!r} until {row['expires_at']}"
                )
        return self.get_lease(tenant_id, resource_id)

    def renew_lease(
        self,
        tenant_id: str,
        resource_id: str,
        holder_id: str,
        fencing_token: int,
        *,
        ttl_seconds: int,
        now: int | None = None,
    ) -> Lease:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        timestamp = self._timestamp(now)
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE leases SET heartbeat_at=?,expires_at=? WHERE tenant_id=? "
                "AND resource_id=? AND holder_id=? AND fencing_token=? AND expires_at>?",
                (
                    timestamp,
                    timestamp + ttl_seconds,
                    tenant_id,
                    resource_id,
                    holder_id,
                    fencing_token,
                    timestamp,
                ),
            )
            if cursor.rowcount != 1:
                raise ConflictError("lease token is stale, released, or expired")
        return self.get_lease(tenant_id, resource_id)

    def release_lease(
        self, tenant_id: str, resource_id: str, holder_id: str, fencing_token: int
    ) -> Lease:
        now = self._now()
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE leases SET holder_id=NULL,heartbeat_at=?,expires_at=? "
                "WHERE tenant_id=? AND resource_id=? AND holder_id=? AND fencing_token=?",
                (now, now, tenant_id, resource_id, holder_id, fencing_token),
            )
            if cursor.rowcount != 1:
                raise ConflictError("lease token is stale or already released")
        return self.get_lease(tenant_id, resource_id)

    def get_lease(self, tenant_id: str, resource_id: str) -> Lease:
        row = self._fetchone(
            "SELECT * FROM leases WHERE tenant_id=? AND resource_id=?",
            (tenant_id, resource_id),
        )
        if row is None:
            raise NotFoundError("lease not found")
        return Lease(**dict(row))

    def create_budget(
        self, tenant_id: str, budget_id: str, limit_units: int
    ) -> BudgetSnapshot:
        _required(tenant_id=tenant_id, budget_id=budget_id)
        _nonnegative_int(limit_units, "limit_units")
        now = self._now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM budgets WHERE tenant_id=? AND budget_id=?",
                (tenant_id, budget_id),
            ).fetchone()
            if row is not None:
                if row["limit_units"] != limit_units:
                    raise ConflictError("budget already exists with a different limit")
                return _budget(row)
            connection.execute(
                "INSERT INTO budgets(tenant_id,budget_id,limit_units,reserved_units,"
                "consumed_units,version,created_at,updated_at) VALUES (?,?,?,0,0,0,?,?)",
                (tenant_id, budget_id, limit_units, now, now),
            )
        return self.get_budget(tenant_id, budget_id)

    def reserve_budget(
        self,
        tenant_id: str,
        budget_id: str,
        reservation_id: str,
        units: int,
    ) -> BudgetSnapshot:
        _required(tenant_id=tenant_id, budget_id=budget_id, reservation_id=reservation_id)
        _positive_int(units, "units")
        now = self._now()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM budget_reservations WHERE tenant_id=? AND budget_id=? "
                "AND reservation_id=?",
                (tenant_id, budget_id, reservation_id),
            ).fetchone()
            if existing is not None:
                if existing["units"] != units:
                    raise ConflictError("reservation ID was used for a different amount")
                return self._budget_in_transaction(connection, tenant_id, budget_id)
            budget = self._budget_row(connection, tenant_id, budget_id)
            available = (
                int(budget["limit_units"])
                - int(budget["reserved_units"])
                - int(budget["consumed_units"])
            )
            if units > available:
                raise BudgetExceededError(
                    f"reservation needs {units} units but only {available} remain"
                )
            connection.execute(
                "UPDATE budgets SET reserved_units=reserved_units+?,version=version+1,"
                "updated_at=? WHERE tenant_id=? AND budget_id=?",
                (units, now, tenant_id, budget_id),
            )
            connection.execute(
                "INSERT INTO budget_reservations VALUES (?,?,?,?,'RESERVED',?,?)",
                (tenant_id, budget_id, reservation_id, units, now, now),
            )
            return self._budget_in_transaction(connection, tenant_id, budget_id)

    def consume_budget(
        self, tenant_id: str, budget_id: str, reservation_id: str
    ) -> BudgetSnapshot:
        return self._transition_reservation(
            tenant_id, budget_id, reservation_id, "CONSUMED"
        )

    def release_budget(
        self, tenant_id: str, budget_id: str, reservation_id: str
    ) -> BudgetSnapshot:
        return self._transition_reservation(
            tenant_id, budget_id, reservation_id, "RELEASED"
        )

    def _transition_reservation(
        self, tenant_id: str, budget_id: str, reservation_id: str, target: str
    ) -> BudgetSnapshot:
        now = self._now()
        with self.transaction() as connection:
            reservation = connection.execute(
                "SELECT * FROM budget_reservations WHERE tenant_id=? AND budget_id=? "
                "AND reservation_id=?",
                (tenant_id, budget_id, reservation_id),
            ).fetchone()
            if reservation is None:
                raise NotFoundError("budget reservation not found")
            if reservation["status"] == target:
                return self._budget_in_transaction(connection, tenant_id, budget_id)
            if reservation["status"] != "RESERVED":
                raise ConflictError(
                    f"cannot change {reservation['status']} reservation to {target}"
                )
            units = int(reservation["units"])
            consumed_delta = units if target == "CONSUMED" else 0
            connection.execute(
                "UPDATE budgets SET reserved_units=reserved_units-?,"
                "consumed_units=consumed_units+?,version=version+1,updated_at=? "
                "WHERE tenant_id=? AND budget_id=?",
                (units, consumed_delta, now, tenant_id, budget_id),
            )
            connection.execute(
                "UPDATE budget_reservations SET status=?,updated_at=? WHERE tenant_id=? "
                "AND budget_id=? AND reservation_id=?",
                (target, now, tenant_id, budget_id, reservation_id),
            )
            return self._budget_in_transaction(connection, tenant_id, budget_id)

    def get_budget(self, tenant_id: str, budget_id: str) -> BudgetSnapshot:
        row = self._fetchone(
            "SELECT * FROM budgets WHERE tenant_id=? AND budget_id=?",
            (tenant_id, budget_id),
        )
        if row is None:
            raise NotFoundError("budget not found")
        return _budget(row)

    @staticmethod
    def _budget_row(
        connection: sqlite3.Connection, tenant_id: str, budget_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM budgets WHERE tenant_id=? AND budget_id=?",
            (tenant_id, budget_id),
        ).fetchone()
        if row is None:
            raise NotFoundError("budget not found")
        return row

    def _budget_in_transaction(
        self, connection: sqlite3.Connection, tenant_id: str, budget_id: str
    ) -> BudgetSnapshot:
        return _budget(self._budget_row(connection, tenant_id, budget_id))

    def register_policy_artifact(
        self,
        tenant_id: str,
        artifact_id: str,
        policy_name: str,
        version: str,
        content_sha256: str,
        artifact_uri: str,
        *,
        metadata: JSONValue | None = None,
    ) -> dict[str, Any]:
        _required(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            policy_name=policy_name,
            version=version,
            artifact_uri=artifact_uri,
        )
        _sha256(content_sha256)
        metadata_json = _json_text({} if metadata is None else metadata)
        now = self._now()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM policy_artifacts WHERE tenant_id=? AND artifact_id=?",
                (tenant_id, artifact_id),
            ).fetchone()
            if existing is not None:
                expected = (
                    policy_name,
                    version,
                    content_sha256,
                    artifact_uri,
                    metadata_json,
                )
                actual = tuple(
                    existing[name]
                    for name in (
                        "policy_name",
                        "version",
                        "content_sha256",
                        "artifact_uri",
                        "metadata_json",
                    )
                )
                if actual != expected:
                    raise ConflictError("artifact ID is bound to different immutable content")
                return _artifact_dict(existing)
            try:
                connection.execute(
                    "INSERT INTO policy_artifacts VALUES (?,?,?,?,?,?,?,?)",
                    (
                        tenant_id,
                        artifact_id,
                        policy_name,
                        version,
                        content_sha256,
                        artifact_uri,
                        metadata_json,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("policy version already exists") from exc
        return self.get_policy_artifact(tenant_id, artifact_id)

    def get_policy_artifact(self, tenant_id: str, artifact_id: str) -> dict[str, Any]:
        row = self._fetchone(
            "SELECT * FROM policy_artifacts WHERE tenant_id=? AND artifact_id=?",
            (tenant_id, artifact_id),
        )
        if row is None:
            raise NotFoundError("policy artifact not found")
        return _artifact_dict(row)

    def record_training_run(
        self,
        tenant_id: str,
        training_id: str,
        policy_name: str,
        artifact_id: str,
        trained_by: str,
        lease_fencing_token: int,
        report: JSONValue,
    ) -> TrainingRun:
        """Record one invocation without changing content-addressed artifact metadata."""

        _required(
            tenant_id=tenant_id,
            training_id=training_id,
            policy_name=policy_name,
            artifact_id=artifact_id,
            trained_by=trained_by,
        )
        _positive_int(lease_fencing_token, "lease_fencing_token")
        report_json = _json_text(report)
        now = self._now()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM training_runs WHERE tenant_id=? AND training_id=?",
                (tenant_id, training_id),
            ).fetchone()
            if existing is not None:
                expected = (
                    policy_name,
                    artifact_id,
                    trained_by,
                    lease_fencing_token,
                    report_json,
                )
                actual = tuple(
                    existing[name]
                    for name in (
                        "policy_name",
                        "artifact_id",
                        "trained_by",
                        "lease_fencing_token",
                        "report_json",
                    )
                )
                if actual != expected:
                    raise ConflictError(
                        "training ID is bound to different immutable provenance"
                    )
                return _training_run(existing)
            artifact = connection.execute(
                "SELECT policy_name FROM policy_artifacts "
                "WHERE tenant_id=? AND artifact_id=?",
                (tenant_id, artifact_id),
            ).fetchone()
            if artifact is None:
                raise NotFoundError("trained policy artifact not found")
            if artifact["policy_name"] != policy_name:
                raise ConflictError("trained artifact belongs to a different policy")
            try:
                connection.execute(
                    "INSERT INTO training_runs(tenant_id,training_id,policy_name,"
                    "artifact_id,trained_by,lease_fencing_token,report_json,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        tenant_id,
                        training_id,
                        policy_name,
                        artifact_id,
                        trained_by,
                        lease_fencing_token,
                        report_json,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("training provenance identity already exists") from exc
            row = connection.execute(
                "SELECT * FROM training_runs WHERE tenant_id=? AND training_id=?",
                (tenant_id, training_id),
            ).fetchone()
            return _training_run(row)

    def list_training_runs(
        self, tenant_id: str, artifact_id: str, *, limit: int = 1000
    ) -> list[TrainingRun]:
        _required(tenant_id=tenant_id, artifact_id=artifact_id)
        _positive_limit(limit)
        rows = self._fetchall(
            "SELECT * FROM training_runs WHERE tenant_id=? AND artifact_id=? "
            "ORDER BY created_at,training_id LIMIT ?",
            (tenant_id, artifact_id, limit),
        )
        return [_training_run(row) for row in rows]

    def training_producers(
        self, tenant_id: str, artifact_id: str
    ) -> frozenset[str]:
        """Return every producer; separation checks must not use a capped query."""

        _required(tenant_id=tenant_id, artifact_id=artifact_id)
        rows = self._fetchall(
            "SELECT DISTINCT trained_by FROM training_runs "
            "WHERE tenant_id=? AND artifact_id=?",
            (tenant_id, artifact_id),
        )
        return frozenset(str(row["trained_by"]) for row in rows)

    def promote_policy(
        self,
        tenant_id: str,
        policy_name: str,
        artifact_id: str,
        *,
        expected_current_artifact_id: str | None,
        decided_by: str,
        reason: str,
        benchmark_receipt_id: str | None = None,
        audit_id: str | None = None,
    ) -> Promotion:
        _required(
            tenant_id=tenant_id,
            policy_name=policy_name,
            artifact_id=artifact_id,
            decided_by=decided_by,
            reason=reason,
        )
        now = self._now()
        audit_id = audit_id or uuid.uuid4().hex
        with self.transaction() as connection:
            artifact = connection.execute(
                "SELECT * FROM policy_artifacts WHERE tenant_id=? AND artifact_id=?",
                (tenant_id, artifact_id),
            ).fetchone()
            if artifact is None:
                raise NotFoundError("candidate policy artifact not found")
            if artifact["policy_name"] != policy_name:
                raise ConflictError("artifact belongs to a different policy")
            current = connection.execute(
                "SELECT * FROM champion_registry WHERE tenant_id=? AND policy_name=?",
                (tenant_id, policy_name),
            ).fetchone()
            current_id = None if current is None else str(current["artifact_id"])
            if expected_current_artifact_id != current_id:
                raise ConflictError(
                    f"champion is {current_id!r}, expected {expected_current_artifact_id!r}"
                )
            if current_id == artifact_id:
                audit = connection.execute(
                    "SELECT * FROM promotion_audit WHERE tenant_id=? AND policy_name=? "
                    "AND generation=?",
                    (tenant_id, policy_name, current["generation"]),
                ).fetchone()
                return _promotion(audit)
            generation = 1 if current is None else int(current["generation"]) + 1
            connection.execute(
                "INSERT INTO champion_registry(tenant_id,policy_name,artifact_id,generation,"
                "promoted_at) VALUES (?,?,?,?,?) ON CONFLICT(tenant_id,policy_name) "
                "DO UPDATE SET artifact_id=excluded.artifact_id,generation=excluded.generation,"
                "promoted_at=excluded.promoted_at",
                (tenant_id, policy_name, artifact_id, generation, now),
            )
            try:
                connection.execute(
                    "INSERT INTO promotion_audit VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        audit_id,
                        tenant_id,
                        policy_name,
                        artifact_id,
                        current_id,
                        generation,
                        decided_by,
                        reason,
                        benchmark_receipt_id,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("promotion audit identity already exists") from exc
            audit = connection.execute(
                "SELECT * FROM promotion_audit WHERE tenant_id=? AND audit_id=?",
                (tenant_id, audit_id),
            ).fetchone()
            return _promotion(audit)

    def get_champion(self, tenant_id: str, policy_name: str) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT c.tenant_id,c.policy_name,c.artifact_id,c.generation,c.promoted_at,"
            "a.version,a.content_sha256,a.artifact_uri,a.metadata_json "
            "FROM champion_registry c JOIN policy_artifacts a "
            "ON a.tenant_id=c.tenant_id AND a.artifact_id=c.artifact_id "
            "WHERE c.tenant_id=? AND c.policy_name=?",
            (tenant_id, policy_name),
        )
        if row is None:
            return None
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        return result

    def get_promotion_at_generation(
        self,
        tenant_id: str,
        policy_name: str,
        generation: int,
    ) -> Promotion | None:
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            raise ValueError("generation must be a positive integer")
        row = self._fetchone(
            "SELECT * FROM promotion_audit WHERE tenant_id=? AND policy_name=? "
            "AND generation=?",
            (tenant_id, policy_name, generation),
        )
        return None if row is None else _promotion(row)

    def list_promotion_audit(
        self, tenant_id: str, policy_name: str, *, limit: int = 1000
    ) -> list[Promotion]:
        _positive_limit(limit)
        rows = self._fetchall(
            "SELECT * FROM promotion_audit WHERE tenant_id=? AND policy_name=? "
            "ORDER BY generation LIMIT ?",
            (tenant_id, policy_name, limit),
        )
        return [_promotion(row) for row in rows]

    def checkpoint(self, mode: str = "PASSIVE") -> tuple[int, int, int]:
        normalized = mode.upper()
        if normalized not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
            raise ValueError("unsupported WAL checkpoint mode")
        row = self._fetchone(f"PRAGMA wal_checkpoint({normalized})")
        if row is None:
            raise StoreError("SQLite did not return a WAL checkpoint result")
        return tuple(int(value) for value in row)

    def integrity_check(self) -> tuple[str, ...]:
        return tuple(str(row[0]) for row in self._fetchall("PRAGMA integrity_check"))

    def readiness_check(self) -> dict[str, Any]:
        """Run bounded connection/config checks suitable for frequent probes."""

        probe = self._fetchone("SELECT 1")
        journal_row = self._fetchone("PRAGMA journal_mode")
        foreign_keys_row = self._fetchone("PRAGMA foreign_keys")
        schema_version = self.schema_version()
        journal_mode = str(journal_row[0]).lower() if journal_row is not None else ""
        foreign_keys = (
            bool(foreign_keys_row[0]) if foreign_keys_row is not None else False
        )
        return {
            "ok": (
                probe is not None
                and int(probe[0]) == 1
                and schema_version == SCHEMA_VERSION
                and journal_mode == "wal"
                and foreign_keys
            ),
            "schema_version": schema_version,
            "journal_mode": journal_mode,
            "foreign_keys": foreign_keys,
        }

    def health(self) -> dict[str, Any]:
        readiness = self.readiness_check()
        integrity = self.integrity_check()
        return {
            **readiness,
            "ok": bool(readiness["ok"]) and integrity == ("ok",),
            "integrity": list(integrity),
        }

    def backup(self, destination: str | Path) -> Path:
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            backup_connection = sqlite3.connect(str(target))
            try:
                self._connection.backup(backup_connection)
            finally:
                backup_connection.close()
        return target

    def _now(self) -> int:
        return int(self._clock())

    def _timestamp(self, value: int | None) -> int:
        result = self._now() if value is None else value
        if not isinstance(result, int) or isinstance(result, bool) or result < 0:
            raise ValueError("timestamp must be a nonnegative integer")
        return result


def _required(**values: str) -> None:
    for name, value in values.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a nonempty string")


def _json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _sha256(value: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise StoreError("SHA-256 values must be 64 lowercase hexadecimal characters")


def _payload_text(payload: Mapping[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise StoreError(f"receipt payload {name!r} must be a nonempty string")
    return value


def _optional_payload_text(payload: Mapping[str, Any], name: str) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise StoreError(f"receipt payload {name!r} must be a nonempty string or null")
    return value


def _positive_limit(value: int) -> None:
    _positive_int(value, "limit")
    if value > 100_000:
        raise ValueError("limit must not exceed 100000")


def _positive_int(value: int, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _nonnegative_int(value: int, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


def _event_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["payload"] = json.loads(result.pop("payload_json"))
    return result


def _experience_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["payload"] = json.loads(result.pop("payload_json"))
    result["envelope"] = json.loads(result.pop("envelope_json"))
    return result


def _idempotency_record(row: sqlite3.Row, *, is_new: bool) -> IdempotencyRecord:
    result = None if row["result_json"] is None else json.loads(row["result_json"])
    return IdempotencyRecord(
        tenant_id=row["tenant_id"],
        scope=row["scope"],
        key=row["idempotency_key"],
        request_hash=row["request_hash"],
        status=row["status"],
        result=result,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        expires_at=row["expires_at"],
        is_new=is_new,
    )


def _budget(row: sqlite3.Row) -> BudgetSnapshot:
    limit_units = int(row["limit_units"])
    reserved_units = int(row["reserved_units"])
    consumed_units = int(row["consumed_units"])
    return BudgetSnapshot(
        tenant_id=row["tenant_id"],
        budget_id=row["budget_id"],
        limit_units=limit_units,
        reserved_units=reserved_units,
        consumed_units=consumed_units,
        available_units=limit_units - reserved_units - consumed_units,
        version=int(row["version"]),
    )


def _artifact_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["metadata"] = json.loads(result.pop("metadata_json"))
    return result


def _training_run(row: sqlite3.Row) -> TrainingRun:
    result = dict(row)
    result["report"] = json.loads(result.pop("report_json"))
    return TrainingRun(**result)


def _promotion(row: sqlite3.Row) -> Promotion:
    return Promotion(**dict(row))


__all__ = [
    "BudgetExceededError",
    "BudgetSnapshot",
    "ConflictError",
    "IdempotencyRecord",
    "Lease",
    "LeaseUnavailableError",
    "NotFoundError",
    "Promotion",
    "SCHEMA_VERSION",
    "SQLiteStore",
    "StoreConfigurationError",
    "StoreError",
    "TrainingRun",
]
