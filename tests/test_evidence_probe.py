from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tree_rl.workers.evidence_probe import _sha256_file


@unittest.skipUnless(os.name == "posix", "secure dirfd traversal requires POSIX")
class EvidenceProbeTests(unittest.TestCase):
    def test_hashes_nested_regular_file_from_real_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            artifact = nested / "artifact.bin"
            artifact.write_bytes(b"proof")
            previous = Path.cwd()
            os.chdir(root)
            try:
                result = _sha256_file("nested/artifact.bin")
            finally:
                os.chdir(previous)

            self.assertEqual(5, result["size_bytes"])
            self.assertEqual(hashlib.sha256(b"proof").hexdigest(), result["sha256"])

    def test_rejects_final_and_parent_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            target = outside / "target.bin"
            target.write_bytes(b"secret")
            final_link = root / "final-link"
            final_link.symlink_to(target)
            parent_link = root / "parent-link"
            parent_link.symlink_to(outside, target_is_directory=True)
            previous = Path.cwd()
            os.chdir(root)
            try:
                with self.assertRaisesRegex(ValueError, "opened securely"):
                    _sha256_file("final-link")
                with self.assertRaisesRegex(ValueError, "opened securely"):
                    _sha256_file("parent-link/target.bin")
            finally:
                os.chdir(previous)

    def test_detects_in_place_change_while_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"a" * (2 * 1024 * 1024))
            previous = Path.cwd()
            real_read = os.read
            changed = False

            def mutate_after_read(descriptor: int, size: int) -> bytes:
                nonlocal changed
                chunk = real_read(descriptor, size)
                if chunk and not changed:
                    changed = True
                    with artifact.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(b"b")
                        handle.flush()
                        os.fsync(handle.fileno())
                return chunk

            os.chdir(root)
            try:
                with mock.patch(
                    "agent_tree_rl.workers.evidence_probe.os.read",
                    side_effect=mutate_after_read,
                ):
                    with self.assertRaisesRegex(ValueError, "changed while hashing"):
                        _sha256_file("artifact.bin")
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
