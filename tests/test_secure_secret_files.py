from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from agent_tree_rl.config import (
    MAX_PRIVATE_JSON_BYTES,
    ConfigurationError,
    Settings,
    _secure_json,
)
from agent_tree_rl import cli as cli_module
from agent_tree_rl import secrets as secrets_module
from agent_tree_rl.cli import build_runtime, command_init
from agent_tree_rl.evidence import PolicyViolation
from agent_tree_rl.secrets import initialize_keyring, initialize_secrets, load_keyring


class SecureSecretFileTests(unittest.TestCase):
    def _private_json(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    def test_settings_rejects_token_file_symlink_before_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "tokens-target.json"
            self._private_json(
                target,
                {
                    "0" * 64: {
                        "tenant_id": "tenant-a",
                        "roles": ["agent"],
                        "subject_id": "subject-a",
                    }
                },
            )
            link = root / "tokens.json"
            link.symlink_to(target)

            with self.assertRaisesRegex(ConfigurationError, "symlink"):
                Settings.from_env(
                    {
                        "AGENT_TREE_RL_DATA_DIR": str(root / "data"),
                        "AGENT_TREE_RL_ADMIN_TOKEN_FILE": str(link),
                    }
                )

    def test_keyring_loader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "keyring-target.json"
            self._private_json(
                target,
                {"active_key_id": "key-a", "keys": {"key-a": "A" * 43}},
            )
            link = root / "keyring.json"
            link.symlink_to(target)

            with self.assertRaisesRegex(ConfigurationError, "symlink"):
                load_keyring(link)

    def test_secret_json_read_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b" " * (MAX_PRIVATE_JSON_BYTES + 1))
            path.chmod(0o600)

            with self.assertRaisesRegex(ConfigurationError, "exceeds"):
                _secure_json(path)

    def test_secret_json_requires_private_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exposed = root / "exposed.json"
            self._private_json(exposed, {"ok": True})
            exposed.chmod(0o640)
            with self.assertRaisesRegex(ConfigurationError, "group/world"):
                _secure_json(exposed)

            with self.assertRaisesRegex(ConfigurationError, "regular file"):
                _secure_json(root)

    def test_path_replacement_between_check_and_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "secret.json"
            replacement = root / "replacement.json"
            self._private_json(path, {"version": "checked"})
            self._private_json(replacement, {"version": "opened"})
            real_open = os.open

            def replace_then_open(
                candidate: os.PathLike[str] | str, flags: int, *args: object
            ) -> int:
                os.replace(replacement, path)
                return real_open(candidate, flags, *args)

            with mock.patch("agent_tree_rl.config.os.open", side_effect=replace_then_open):
                with self.assertRaisesRegex(ConfigurationError, "changed while opening"):
                    _secure_json(path)

    def test_regular_private_keyring_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keyring.json"
            self._private_json(
                path,
                {"active_key_id": "key-a", "keys": {"key-a": "A" * 43}},
            )

            keys, active = load_keyring(path)

            self.assertEqual("key-a", active)
            self.assertGreaterEqual(len(keys[active]), 32)

    def test_bootstrap_tokens_are_written_privately_and_never_to_hash_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keyring = root / "receipt-keys.json"
            token_hashes = root / "api-tokens.json"
            plaintext = root / "bootstrap-tokens.json"

            initialize_secrets(
                keyring_path=keyring,
                token_path=token_hashes,
                plaintext_token_path=plaintext,
                tenant_id="tenant-a",
            )

            for path in (keyring, token_hashes, plaintext):
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            bootstrap = json.loads(plaintext.read_text(encoding="utf-8"))
            hashed = json.loads(token_hashes.read_text(encoding="utf-8"))
            for token in bootstrap["api_tokens"].values():
                self.assertNotIn(token, token_hashes.read_text(encoding="utf-8"))
                self.assertIn(hashlib.sha256(token.encode()).hexdigest(), hashed)

    def test_bootstrap_refuses_existing_output_before_creating_other_secrets(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keyring = root / "receipt-keys.json"
            token_hashes = root / "api-tokens.json"
            plaintext = root / "bootstrap-tokens.json"
            plaintext.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "overwrite"):
                initialize_secrets(
                    keyring_path=keyring,
                    token_path=token_hashes,
                    plaintext_token_path=plaintext,
                )

            self.assertEqual("keep", plaintext.read_text(encoding="utf-8"))
            self.assertFalse(keyring.exists())
            self.assertFalse(token_hashes.exists())

    def test_bootstrap_interrupt_removes_temporary_and_published_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch(
                "agent_tree_rl.secrets.os.link",
                side_effect=KeyboardInterrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    initialize_secrets(
                        keyring_path=root / "receipt-keys.json",
                        token_path=root / "api-tokens.json",
                        plaintext_token_path=root / "bootstrap-tokens.json",
                    )

            self.assertEqual([], list(root.iterdir()))

    def test_link_then_interrupt_removes_the_published_secret_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_link = os.link

            def link_then_interrupt(source: str, destination: Path) -> None:
                real_link(source, destination)
                raise KeyboardInterrupt

            with mock.patch(
                "agent_tree_rl.secrets.os.link",
                side_effect=link_then_interrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    initialize_keyring(root / "receipt-keys.json")

            self.assertEqual([], list(root.iterdir()))

    def test_keyring_close_failure_rolls_back_published_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_close = os.close
            close_calls = 0

            def close_then_fail_on_created_file(descriptor: int) -> None:
                nonlocal close_calls
                close_calls += 1
                real_close(descriptor)
                if close_calls == 2:
                    raise OSError("simulated creation descriptor close failure")

            with mock.patch(
                "agent_tree_rl.secrets.os.close",
                side_effect=close_then_fail_on_created_file,
            ):
                with self.assertRaisesRegex(OSError, "creation descriptor"):
                    initialize_keyring(root / "receipt-keys.json")

            self.assertEqual([], list(root.iterdir()))

    def test_private_write_cleanup_preserves_a_substituted_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.key"
            real_fsync = os.fsync

            def substitute_then_fail(descriptor: int) -> None:
                real_fsync(descriptor)
                path.unlink()
                path.write_text("replacement", encoding="utf-8")
                raise OSError("simulated fsync failure")

            with mock.patch(
                "agent_tree_rl.cli.os.fsync",
                side_effect=substitute_then_fail,
            ):
                with self.assertRaisesRegex(OSError, "simulated"):
                    cli_module._write_private_exclusive(path, b"sensitive")

            self.assertEqual("replacement", path.read_text(encoding="utf-8"))

    def test_private_write_close_failure_rolls_back_created_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.key"
            real_close = os.close

            def close_then_fail(descriptor: int) -> None:
                real_close(descriptor)
                raise OSError("simulated private descriptor close failure")

            with mock.patch(
                "agent_tree_rl.cli.os.close",
                side_effect=close_then_fail,
            ):
                with self.assertRaisesRegex(OSError, "private descriptor"):
                    cli_module._write_private_exclusive(path, b"sensitive")

            self.assertFalse(path.exists())

    def test_bootstrap_cleanup_preserves_a_substituted_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keyring = root / "receipt-keys.json"
            token_hashes = root / "api-tokens.json"
            plaintext = root / "bootstrap-tokens.json"
            real_atomic = secrets_module._atomic_private_json

            def substitute_then_fail(
                path: Path,
                payload: dict[str, object],
                *,
                replace: bool = True,
                creation_log: list[secrets_module.CreatedFile] | None = None,
            ) -> secrets_module.FileIdentity:
                if path == plaintext:
                    keyring.unlink()
                    keyring.write_text("replacement", encoding="utf-8")
                    raise OSError("simulated plaintext write failure")
                return real_atomic(
                    path,
                    payload,
                    replace=replace,
                    creation_log=creation_log,
                )

            with mock.patch(
                "agent_tree_rl.secrets._atomic_private_json",
                side_effect=substitute_then_fail,
            ):
                with self.assertRaisesRegex(OSError, "simulated"):
                    initialize_secrets(
                        keyring_path=keyring,
                        token_path=token_hashes,
                        plaintext_token_path=plaintext,
                    )

            self.assertEqual("replacement", keyring.read_text(encoding="utf-8"))
            self.assertFalse(token_hashes.exists())
            self.assertFalse(plaintext.exists())

    def test_init_rejects_colliding_paths_before_writing_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "data"
            with self.assertRaisesRegex(ValueError, "distinct"):
                command_init(
                    argparse.Namespace(
                        data_dir=str(root),
                        tenant="tenant-a",
                        token_output=str(root / "backup-keys.json"),
                    )
                )

            self.assertEqual([], list(root.iterdir()))

    def test_init_rolls_back_files_when_late_bootstrap_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "data"
            real_write = cli_module._write_private_exclusive

            def fail_sample(
                path: Path,
                data: bytes,
                *,
                creation_log: list[secrets_module.CreatedFile] | None = None,
            ) -> None:
                if path.name == "policy.json":
                    raise OSError("simulated sample write failure")
                real_write(path, data, creation_log=creation_log)

            with mock.patch(
                "agent_tree_rl.cli._write_private_exclusive",
                side_effect=fail_sample,
            ):
                with self.assertRaisesRegex(OSError, "simulated"):
                    command_init(
                        argparse.Namespace(
                            data_dir=str(root),
                            tenant="tenant-a",
                            token_output=None,
                        )
                    )

            self.assertEqual([], list(root.iterdir()))

    def test_init_rollback_removes_a_created_directory_after_it_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "data"
            real_write = cli_module._write_private_exclusive

            def fail_after_directory_change(
                path: Path,
                data: bytes,
                *,
                creation_log: list[secrets_module.CreatedFile] | None = None,
            ) -> None:
                if path.name == "policy.json":
                    path.write_bytes(b"partial")
                    path.unlink()
                    raise OSError("simulated post-create failure")
                real_write(path, data, creation_log=creation_log)

            with mock.patch(
                "agent_tree_rl.cli._write_private_exclusive",
                side_effect=fail_after_directory_change,
            ):
                with self.assertRaisesRegex(OSError, "post-create"):
                    command_init(
                        argparse.Namespace(
                            data_dir=str(root),
                            tenant="tenant-a",
                            token_output=None,
                        )
                    )

            self.assertEqual([], list(root.iterdir()))

    def test_init_rollback_removes_directory_when_opening_it_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "data"
            benchmark_dir = root.resolve() / "benchmarks"
            real_open = os.open

            def fail_benchmark_directory_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if Path(path) == benchmark_dir:
                    raise OSError("simulated directory open failure")
                return real_open(path, flags, *args, **kwargs)

            with mock.patch(
                "agent_tree_rl.cli.os.open",
                side_effect=fail_benchmark_directory_open,
            ):
                with self.assertRaisesRegex(OSError, "directory open"):
                    command_init(
                        argparse.Namespace(
                            data_dir=str(root),
                            tenant="tenant-a",
                            token_output=None,
                        )
                    )

            self.assertEqual([], list(root.iterdir()))

    def test_init_rollback_removes_directory_when_identity_read_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "data"
            benchmark_dir = root.resolve() / "benchmarks"
            real_lstat = os.lstat

            def fail_benchmark_directory_identity(
                path: os.PathLike[str] | str,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if Path(path) == benchmark_dir:
                    raise OSError("simulated directory identity failure")
                return real_lstat(path, *args, **kwargs)

            with mock.patch(
                "agent_tree_rl.cli.os.lstat",
                side_effect=fail_benchmark_directory_identity,
            ):
                with self.assertRaisesRegex(OSError, "directory identity"):
                    command_init(
                        argparse.Namespace(
                            data_dir=str(root),
                            tenant="tenant-a",
                            token_output=None,
                        )
                    )

            self.assertEqual([], list(root.iterdir()))

    def test_init_rolls_back_files_when_interrupted_late(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "data"
            real_write = cli_module._write_private_exclusive

            def interrupt_sample(
                path: Path,
                data: bytes,
                *,
                creation_log: list[secrets_module.CreatedFile] | None = None,
            ) -> None:
                if path.name == "policy.json":
                    raise KeyboardInterrupt
                real_write(path, data, creation_log=creation_log)

            with mock.patch(
                "agent_tree_rl.cli._write_private_exclusive",
                side_effect=interrupt_sample,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    command_init(
                        argparse.Namespace(
                            data_dir=str(root),
                            tenant="tenant-a",
                            token_output=None,
                        )
                    )

            self.assertEqual([], list(root.iterdir()))

    def test_runtime_rejects_symlinked_benchmark_signing_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keyring = root / "receipt-keys.json"
            self._private_json(
                keyring,
                {"active_key_id": "key-a", "keys": {"key-a": "A" * 43}},
            )
            target = root / "benchmark-target.key"
            target.write_bytes(b"b" * 32)
            target.chmod(0o600)
            link = root / "benchmark.key"
            link.symlink_to(target)
            settings = Settings(
                host="127.0.0.1",
                port=0,
                data_dir=root / "data",
                database_path=root / "data" / "control.sqlite3",
                receipt_keys_file=keyring,
                admin_token_file=root / "unused-tokens.json",
                benchmark_dir=root,
                benchmark_signing_key_file=link,
                require_auth=False,
            )

            with self.assertRaisesRegex(PolicyViolation, "symlink"):
                build_runtime(settings)

    def test_settings_rejects_disguised_interpreter_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disguised = root / "safe-probe"
            disguised.symlink_to(Path(sys.executable).resolve())
            settings = Settings(
                host="127.0.0.1",
                port=0,
                data_dir=root / "data",
                database_path=root / "data" / "control.sqlite3",
                receipt_keys_file=root / "unused-keys.json",
                admin_token_file=root / "unused-tokens.json",
                benchmark_dir=root,
                require_auth=False,
                allowed_commands=(str(disguised),),
                allowed_cwd_roots=(root,),
            )

            with self.assertRaisesRegex(ConfigurationError, "symlink"):
                settings.validate()


if __name__ == "__main__":
    unittest.main()
