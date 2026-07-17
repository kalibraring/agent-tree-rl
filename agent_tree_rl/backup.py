"""Authenticated, relocatable backup bundles for SQLite state and policy objects."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import tempfile
import time
from typing import Any, Mapping
import zipfile

from . import __version__
from .artifacts import (
    MAX_POLICY_BYTES,
    policy_artifact_path,
    policy_artifact_uri,
    read_verified_policy,
    tenant_namespace,
)
from .crypto import canonical_json_bytes
from .store import SCHEMA_VERSION, SQLiteStore


FORMAT = "agent-tree-rl-backup"
FORMAT_VERSION = 1
DATABASE_MEMBER = "state.sqlite3"
MANIFEST_MEMBER = "manifest.json"
SIGNATURE_MEMBER = "manifest.hmac.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_DATABASE_BYTES = 64 * 1024 * 1024 * 1024
MAX_BUNDLE_CONTENT_BYTES = 128 * 1024 * 1024 * 1024
RESTORE_MARKER = ".agent-tree-rl-restore.json"


class BackupError(RuntimeError):
    pass


def create_bundle(
    store: SQLiteStore,
    artifact_root: Path,
    output: Path | str,
    keys: Mapping[str, bytes],
    active_key_id: str,
) -> Path:
    target = Path(output).expanduser().resolve()
    if target.exists():
        raise FileExistsError(f"refusing to overwrite backup: {target}")
    if active_key_id not in keys:
        raise BackupError("active backup key is unavailable")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    work = Path(tempfile.mkdtemp(prefix="backup-stage.", dir=target.parent))
    temporary = target.parent / f".{target.name}.{os.getpid()}.tmp"
    try:
        snapshot = work / DATABASE_MEMBER
        store.backup(snapshot)
        database_metadata, artifact_rows, champions = _inspect_snapshot(snapshot)
        objects: dict[str, Path] = {}
        staged_objects = work / "objects"
        staged_objects.mkdir(mode=0o700)
        artifact_manifest: list[dict[str, str]] = []
        for row in artifact_rows:
            tenant_id = row["tenant_id"]
            digest = row["content_sha256"]
            if row["artifact_id"] != "policy-" + digest:
                raise BackupError("policy artifact ID is not content-addressed")
            if row["artifact_uri"] != policy_artifact_uri(tenant_id, digest):
                raise BackupError("policy artifact URI is not canonical")
            if digest not in objects:
                data = read_verified_policy(
                    policy_artifact_path(artifact_root, tenant_id, digest),
                    digest,
                )
                staged_object = staged_objects / digest
                _write_private(staged_object, data, 0o600)
                objects[digest] = staged_object
            artifact_manifest.append(
                {
                    "tenant_namespace": tenant_namespace(tenant_id),
                    "content_sha256": digest,
                }
            )

        object_manifest = [
            {
                "member": _object_member(digest),
                "size_bytes": path.stat().st_size,
                "sha256": digest,
            }
            for digest, path in sorted(objects.items())
        ]
        total_content_size = snapshot.stat().st_size + sum(
            item["size_bytes"] for item in object_manifest
        )
        if total_content_size > MAX_BUNDLE_CONTENT_BYTES:
            raise BackupError("backup content exceeds cumulative size cap")
        manifest = {
            "format": FORMAT,
            "format_version": FORMAT_VERSION,
            "created_at": int(time.time()),
            "service_version": __version__,
            "schema_version": database_metadata["schema_version"],
            "database": {
                "member": DATABASE_MEMBER,
                "size_bytes": snapshot.stat().st_size,
                "sha256": _sha256_file(snapshot, MAX_DATABASE_BYTES),
            },
            "objects": object_manifest,
            "artifacts": sorted(
                artifact_manifest,
                key=lambda item: (item["tenant_namespace"], item["content_sha256"]),
            ),
            "champions": champions,
        }
        manifest_bytes = canonical_json_bytes(manifest)
        signature = hmac.new(keys[active_key_id], manifest_bytes, hashlib.sha256).digest()
        signature_bytes = canonical_json_bytes(
            {
                "algorithm": "HMAC-SHA256",
                "key_id": active_key_id,
                "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
            }
        )
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(MANIFEST_MEMBER, manifest_bytes)
            archive.writestr(SIGNATURE_MEMBER, signature_bytes)
            archive.write(snapshot, DATABASE_MEMBER)
            for digest, path in sorted(objects.items()):
                archive.write(path, _object_member(digest))
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        _fsync_directory(target.parent)
        return target
    finally:
        shutil.rmtree(work, ignore_errors=True)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def restore_bundle(
    source: Path | str,
    database_path: Path,
    artifact_root: Path,
    keys: Mapping[str, bytes],
) -> dict[str, Any]:
    bundle = Path(source).expanduser().resolve(strict=True)
    database_path = database_path.resolve()
    artifact_root = artifact_root.resolve()
    marker = database_path.parent / RESTORE_MARKER
    resumed = _resume_restore(
        bundle, database_path, artifact_root, marker, keys
    )
    if resumed is not None:
        return resumed
    for forbidden in (
        database_path,
        Path(str(database_path) + "-wal"),
        Path(str(database_path) + "-shm"),
        artifact_root,
    ):
        if forbidden.exists():
            raise FileExistsError(f"restore target must be absent: {forbidden}")
    database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    stage = Path(tempfile.mkdtemp(prefix="restore-stage.", dir=database_path.parent))
    installed_artifacts = False
    try:
        with zipfile.ZipFile(bundle, "r") as archive:
            infos = _validate_zip_headers(archive)
            manifest_bytes = _read_member(
                archive, infos[MANIFEST_MEMBER], MAX_MANIFEST_BYTES
            )
            signature_value = _strict_json(
                _read_member(archive, infos[SIGNATURE_MEMBER], 16 * 1024)
            )
            _verify_manifest_signature(manifest_bytes, signature_value, keys)
            manifest = _validate_manifest(_strict_json(manifest_bytes))
            expected_members = {
                MANIFEST_MEMBER,
                SIGNATURE_MEMBER,
                DATABASE_MEMBER,
                *(item["member"] for item in manifest["objects"]),
            }
            if set(infos) != expected_members:
                raise BackupError("bundle members do not exactly match the manifest")
            staged_database = stage / DATABASE_MEMBER
            _copy_verified_member(
                archive,
                infos[DATABASE_MEMBER],
                staged_database,
                manifest["database"]["size_bytes"],
                manifest["database"]["sha256"],
                MAX_DATABASE_BYTES,
            )
            declared_content_size = manifest["database"]["size_bytes"] + sum(
                item["size_bytes"] for item in manifest["objects"]
            )
            if declared_content_size > MAX_BUNDLE_CONTENT_BYTES:
                raise BackupError("bundle content exceeds cumulative size cap")
            staged_objects = stage / "objects"
            staged_objects.mkdir(mode=0o700)
            object_paths: dict[str, Path] = {}
            for item in manifest["objects"]:
                object_path = staged_objects / item["sha256"]
                _copy_verified_member(
                    archive,
                    infos[item["member"]],
                    object_path,
                    item["size_bytes"],
                    item["sha256"],
                    MAX_POLICY_BYTES,
                )
                object_paths[item["sha256"]] = object_path

        metadata, rows, champions = _inspect_snapshot(staged_database)
        if metadata["schema_version"] != manifest["schema_version"]:
            raise BackupError("database schema does not match manifest")
        if champions != manifest["champions"]:
            raise BackupError("champion registry does not match manifest")
        expected_artifacts = sorted(
            (
                tenant_namespace(row["tenant_id"]),
                row["content_sha256"],
            )
            for row in rows
        )
        declared_artifacts = sorted(
            (item["tenant_namespace"], item["content_sha256"])
            for item in manifest["artifacts"]
        )
        if expected_artifacts != declared_artifacts:
            raise BackupError("artifact manifest does not match database rows")
        if {digest for _, digest in expected_artifacts} != set(object_paths):
            raise BackupError("object set does not match database artifacts")
        staged_artifacts = stage / "artifacts"
        staged_artifacts.mkdir(mode=0o750)
        for row in rows:
            tenant_id = row["tenant_id"]
            digest = row["content_sha256"]
            if row["artifact_id"] != "policy-" + digest:
                raise BackupError("restored policy artifact ID is not canonical")
            if row["artifact_uri"] != policy_artifact_uri(tenant_id, digest):
                raise BackupError("restored policy artifact URI is not canonical")
            target = policy_artifact_path(staged_artifacts, tenant_id, digest)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            _copy_private_file(object_paths[digest], target, 0o640)
        _validate_artifact_tree(staged_artifacts, rows)

        marker_payload = {
            "format": "agent-tree-rl-restore/v1",
            "manifest_sha256": hashlib.sha256(
                canonical_json_bytes(manifest)
            ).hexdigest(),
            "database_path": str(database_path),
            "artifact_root": str(artifact_root),
            "stage": str(stage),
            "artifacts": len(rows),
            "objects": len(object_paths),
            "champions": len(champions),
            "schema_version": metadata["schema_version"],
        }
        marker_key_id = signature_value["key_id"]
        marker_bytes = _authenticated_marker(
            marker_payload, marker_key_id, keys[marker_key_id]
        )
        _write_private(marker, marker_bytes, 0o600)
        _fsync_directory(database_path.parent)
        os.replace(staged_artifacts, artifact_root)
        installed_artifacts = True
        _fsync_directory(database_path.parent)
        os.chmod(staged_database, 0o640)
        os.replace(staged_database, database_path)
        _fsync_directory(database_path.parent)
        marker.unlink()
        _fsync_directory(database_path.parent)
        return {
            "restored": str(database_path),
            "schema_version": metadata["schema_version"],
            "artifacts": len(rows),
            "objects": len(object_paths),
            "champions": len(champions),
        }
    except Exception:
        if installed_artifacts and not database_path.exists():
            shutil.rmtree(artifact_root, ignore_errors=True)
        try:
            marker.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if not marker.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _resume_restore(
    bundle: Path,
    database_path: Path,
    artifact_root: Path,
    marker: Path,
    keys: Mapping[str, bytes],
) -> dict[str, Any] | None:
    """Finish an authenticated restore interrupted between atomic renames."""

    if not marker.exists():
        return None
    raw = marker.read_bytes()
    if len(raw) > 16 * 1024:
        raise BackupError("restore recovery marker exceeds size cap")
    value = _verify_recovery_marker(raw, keys)
    expected_keys = {
        "format", "manifest_sha256", "database_path", "artifact_root", "stage",
        "artifacts", "objects", "champions", "schema_version",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise BackupError("restore recovery marker is invalid")
    if (
        value["format"] != "agent-tree-rl-restore/v1"
        or value["database_path"] != str(database_path)
        or value["artifact_root"] != str(artifact_root)
    ):
        raise BackupError("restore recovery marker does not match this request")
    manifest = _authenticated_bundle_manifest(bundle, keys)
    if value["manifest_sha256"] != hashlib.sha256(
        canonical_json_bytes(manifest)
    ).hexdigest():
        raise BackupError("restore recovery marker targets a different manifest")
    stage = Path(value["stage"]).resolve(strict=True)
    if stage.parent != database_path.parent or not stage.name.startswith("restore-stage."):
        raise BackupError("restore recovery stage is outside the data directory")
    staged_database = stage / DATABASE_MEMBER
    staged_artifacts = stage / "artifacts"
    database_candidate = database_path if database_path.exists() else staged_database
    artifact_candidate = artifact_root if artifact_root.exists() else staged_artifacts
    if not database_candidate.is_file() or not artifact_candidate.is_dir():
        raise BackupError("restore recovery stage is incomplete")
    if (
        database_candidate.stat().st_size != manifest["database"]["size_bytes"]
        or _sha256_file(database_candidate, MAX_DATABASE_BYTES)
        != manifest["database"]["sha256"]
    ):
        raise BackupError("restore recovery database does not match bundle")
    metadata, rows, champions = _inspect_snapshot(database_candidate)
    if (
        metadata["schema_version"] != manifest["schema_version"]
        or champions != manifest["champions"]
        or len(rows) != value["artifacts"]
        or len(champions) != value["champions"]
    ):
        raise BackupError("restore recovery database does not match manifest")
    declared_artifacts = sorted(
        (item["tenant_namespace"], item["content_sha256"])
        for item in manifest["artifacts"]
    )
    actual_artifacts = sorted(
        (tenant_namespace(row["tenant_id"]), row["content_sha256"])
        for row in rows
    )
    if declared_artifacts != actual_artifacts:
        raise BackupError("restore recovery artifacts do not match manifest")
    _validate_artifact_tree(artifact_candidate, rows)
    if not artifact_root.exists():
        if not staged_artifacts.is_dir():
            raise BackupError("restore recovery artifact stage is missing")
        os.replace(staged_artifacts, artifact_root)
        _fsync_directory(database_path.parent)
    if not database_path.exists():
        if not staged_database.is_file():
            raise BackupError("restore recovery database stage is missing")
        os.chmod(staged_database, 0o640)
        os.replace(staged_database, database_path)
        _fsync_directory(database_path.parent)
    metadata, rows, champions = _inspect_snapshot(database_path)
    marker.unlink()
    _fsync_directory(database_path.parent)
    shutil.rmtree(stage, ignore_errors=True)
    return {
        "restored": str(database_path),
        "schema_version": metadata["schema_version"],
        "artifacts": len(rows),
        "objects": value["objects"],
        "champions": len(champions),
        "resumed": True,
    }


def _inspect_snapshot(path: Path) -> tuple[dict[str, int], list[dict[str, str]], list[dict[str, Any]]]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        integrity = tuple(row[0] for row in connection.execute("PRAGMA integrity_check"))
        if integrity != ("ok",):
            raise BackupError(f"database integrity failed: {integrity}")
        foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
        if foreign_keys:
            raise BackupError("database foreign-key check failed")
        schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if schema != SCHEMA_VERSION:
            raise BackupError(f"unsupported schema version: {schema}")
        rows = [
            dict(row)
            for row in connection.execute(
                "SELECT tenant_id,artifact_id,content_sha256,artifact_uri "
                "FROM policy_artifacts ORDER BY tenant_id,artifact_id"
            )
        ]
        champions = [
            dict(row)
            for row in connection.execute(
                "SELECT tenant_id,policy_name,artifact_id,generation "
                "FROM champion_registry ORDER BY tenant_id,policy_name"
            )
        ]
    finally:
        connection.close()
    return {"schema_version": schema}, rows, champions


def _validate_artifact_tree(root: Path, rows: list[dict[str, str]]) -> None:
    metadata = os.lstat(root)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BackupError("artifact root must be a regular directory")
    expected: set[str] = set()
    for row in rows:
        tenant_id = row["tenant_id"]
        digest = row["content_sha256"]
        if row["artifact_id"] != "policy-" + digest:
            raise BackupError("policy artifact ID is not canonical")
        if row["artifact_uri"] != policy_artifact_uri(tenant_id, digest):
            raise BackupError("policy artifact URI is not canonical")
        path = policy_artifact_path(root, tenant_id, digest)
        expected.add(path.relative_to(root.resolve()).as_posix())
        read_verified_policy(path, digest)
    actual: set[str] = set()
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in directory_names:
            child = directory_path / name
            child_metadata = os.lstat(child)
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISDIR(
                child_metadata.st_mode
            ):
                raise BackupError("artifact tree contains an unsafe directory")
        for name in file_names:
            child = directory_path / name
            child_metadata = os.lstat(child)
            if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISREG(
                child_metadata.st_mode
            ):
                raise BackupError("artifact tree contains an unsafe file")
            actual.add(child.relative_to(root).as_posix())
    if actual != expected:
        raise BackupError("artifact tree contains missing or unexpected objects")


def _validate_zip_headers(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos: dict[str, zipfile.ZipInfo] = {}
    for info in archive.infolist():
        name = info.filename
        path = PurePosixPath(name)
        if (
            not name
            or "\\" in name
            or "\x00" in name
            or path.is_absolute()
            or ".." in path.parts
            or name.endswith("/")
        ):
            raise BackupError(f"unsafe bundle member: {name!r}")
        if name in infos:
            raise BackupError(f"duplicate bundle member: {name}")
        if info.compress_type != zipfile.ZIP_STORED:
            raise BackupError("unsupported bundle compression")
        if info.flag_bits & 0x1:
            raise BackupError("encrypted ZIP members are unsupported")
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if file_type not in (0, stat.S_IFREG):
            raise BackupError("bundle members must be regular files")
        infos[name] = info
    if MANIFEST_MEMBER not in infos or SIGNATURE_MEMBER not in infos:
        raise BackupError("bundle manifest or signature is missing")
    return infos


def _validate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "format", "format_version", "created_at", "service_version",
        "schema_version", "database", "objects", "artifacts", "champions",
    }:
        raise BackupError("backup manifest shape is invalid")
    if value["format"] != FORMAT or value["format_version"] != FORMAT_VERSION:
        raise BackupError("unsupported backup format")
    if value["schema_version"] != SCHEMA_VERSION:
        raise BackupError("unsupported manifest schema")
    database = value["database"]
    if not isinstance(database, dict) or set(database) != {"member", "size_bytes", "sha256"}:
        raise BackupError("database manifest is invalid")
    if database["member"] != DATABASE_MEMBER:
        raise BackupError("database member is invalid")
    _size_digest(database, MAX_DATABASE_BYTES)
    if not all(isinstance(item, dict) for item in value["objects"]):
        raise BackupError("object manifest is invalid")
    seen_members: set[str] = set()
    seen_digests: set[str] = set()
    for item in value["objects"]:
        if set(item) != {"member", "size_bytes", "sha256"}:
            raise BackupError("object manifest entry is invalid")
        _size_digest(item, MAX_POLICY_BYTES)
        if item["member"] != _object_member(item["sha256"]):
            raise BackupError("object member is not canonical")
        if item["member"] in seen_members or item["sha256"] in seen_digests:
            raise BackupError("duplicate object manifest entry")
        seen_members.add(item["member"])
        seen_digests.add(item["sha256"])
    for item in value["artifacts"]:
        if not isinstance(item, dict) or set(item) != {"tenant_namespace", "content_sha256"}:
            raise BackupError("artifact manifest entry is invalid")
        if len(item["tenant_namespace"]) != 20:
            raise BackupError("tenant namespace is invalid")
        _hex_digest(item["content_sha256"])
    if not isinstance(value["champions"], list):
        raise BackupError("champion manifest is invalid")
    return value


def _verify_manifest_signature(raw: bytes, value: Any, keys: Mapping[str, bytes]) -> None:
    if not isinstance(value, dict) or set(value) != {"algorithm", "key_id", "signature"}:
        raise BackupError("backup signature shape is invalid")
    key_id = value["key_id"]
    if (
        value["algorithm"] != "HMAC-SHA256"
        or not isinstance(key_id, str)
        or key_id not in keys
    ):
        raise BackupError("backup signature key is unsupported")
    try:
        signature = base64.b64decode(
            value["signature"] + "=" * (-len(value["signature"]) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as error:
        raise BackupError("backup signature is invalid base64url") from error
    expected = hmac.new(keys[key_id], raw, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise BackupError("backup manifest authentication failed")


def _authenticated_bundle_manifest(
    bundle: Path, keys: Mapping[str, bytes]
) -> dict[str, Any]:
    with zipfile.ZipFile(bundle, "r") as archive:
        infos = _validate_zip_headers(archive)
        manifest_bytes = _read_member(
            archive, infos[MANIFEST_MEMBER], MAX_MANIFEST_BYTES
        )
        signature = _strict_json(
            _read_member(archive, infos[SIGNATURE_MEMBER], 16 * 1024)
        )
        _verify_manifest_signature(manifest_bytes, signature, keys)
        manifest = _validate_manifest(_strict_json(manifest_bytes))
        expected_members = {
            MANIFEST_MEMBER,
            SIGNATURE_MEMBER,
            DATABASE_MEMBER,
            *(item["member"] for item in manifest["objects"]),
        }
        if set(infos) != expected_members:
            raise BackupError("bundle members do not exactly match the manifest")
        return manifest


def _authenticated_marker(
    payload: Mapping[str, Any], key_id: str, key: bytes
) -> bytes:
    payload_bytes = canonical_json_bytes(payload)
    signature = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    return canonical_json_bytes(
        {
            "payload": dict(payload),
            "authentication": {
                "algorithm": "HMAC-SHA256",
                "key_id": key_id,
                "signature": base64.urlsafe_b64encode(signature)
                .rstrip(b"=")
                .decode("ascii"),
            },
        }
    )


def _verify_recovery_marker(
    raw: bytes, keys: Mapping[str, bytes]
) -> dict[str, Any]:
    envelope = _strict_json(raw)
    if not isinstance(envelope, dict) or set(envelope) != {
        "payload", "authentication"
    }:
        raise BackupError("restore recovery marker envelope is invalid")
    payload = envelope["payload"]
    authentication = envelope["authentication"]
    if not isinstance(payload, dict) or not isinstance(authentication, dict):
        raise BackupError("restore recovery marker fields are invalid")
    if set(authentication) != {"algorithm", "key_id", "signature"}:
        raise BackupError("restore recovery marker authentication is invalid")
    key_id = authentication["key_id"]
    if (
        authentication["algorithm"] != "HMAC-SHA256"
        or not isinstance(key_id, str)
        or key_id not in keys
    ):
        raise BackupError("restore recovery marker key is unsupported")
    try:
        supplied = base64.b64decode(
            authentication["signature"]
            + "=" * (-len(authentication["signature"]) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as error:
        raise BackupError("restore recovery marker signature is invalid") from error
    expected = hmac.new(
        keys[key_id], canonical_json_bytes(payload), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(supplied, expected):
        raise BackupError("restore recovery marker authentication failed")
    return payload


def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise BackupError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BackupError("bundle JSON is invalid") from error


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> bytes:
    if info.file_size < 0 or info.file_size > cap:
        raise BackupError("bundle member exceeds size cap")
    with archive.open(info, "r") as handle:
        data = handle.read(cap + 1)
    if len(data) != info.file_size or len(data) > cap:
        raise BackupError("bundle member size is inconsistent")
    return data


def _copy_verified_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    target: Path,
    expected_size: int,
    expected_digest: str,
    cap: int,
) -> None:
    if (
        info.file_size < 0
        or info.file_size > cap
        or info.file_size != expected_size
    ):
        raise BackupError("bundle member size is inconsistent")
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(info, "r") as source, os.fdopen(
            descriptor, "wb", closefd=True
        ) as destination:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > cap:
                    raise BackupError("bundle member exceeds size cap")
                digest.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if size != expected_size or digest.hexdigest() != expected_digest:
            raise BackupError("bundle member hash or size mismatch")
    except Exception:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise


def _copy_private_file(source: Path, target: Path, mode: int) -> None:
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with source.open("rb") as input_handle, os.fdopen(
            descriptor, "wb", closefd=True
        ) as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
    except Exception:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise


def _write_private(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _size_digest(value: Mapping[str, Any], cap: int) -> None:
    size = value.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= cap:
        raise BackupError("manifest size is invalid")
    _hex_digest(value.get("sha256"))


def _hex_digest(value: Any) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise BackupError("manifest SHA-256 is invalid")


def _object_member(digest: str) -> str:
    _hex_digest(digest)
    return f"objects/sha256/{digest[:2]}/{digest}.json"


def _sha256_file(path: Path, cap: int) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            if size > cap:
                raise BackupError("database snapshot exceeds size cap")
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
