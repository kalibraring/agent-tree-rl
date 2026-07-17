from __future__ import annotations

import json
import os
from pathlib import Path
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
from agent_tree_rl.cli import build_runtime
from agent_tree_rl.evidence import PolicyViolation
from agent_tree_rl.secrets import load_keyring


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
