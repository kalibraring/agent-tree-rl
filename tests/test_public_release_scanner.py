from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.check_public_release import MAX_PUBLIC_FILE_BYTES, _read_text, scan


class PublicReleaseScannerTests(unittest.TestCase):
    def test_custom_named_bootstrap_token_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom-output.png").write_text(
                json.dumps(
                    {
                        "api_tokens": {
                            "agent": "A" * 64,
                            "operator": "B" * 64,
                        },
                        "tenant_id": "tenant-a",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            findings, _ = scan(root, set(), check_git_history=False)

            self.assertIn("bootstrap-bearer-token", {item.rule for item in findings})

    def test_oversized_file_is_rejected_without_content_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "oversized.txt"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_PUBLIC_FILE_BYTES + 1)

            findings, _ = scan(root, set(), check_git_history=False)

            self.assertIn("large-file", {item.rule for item in findings})
            self.assertIsNone(_read_text(oversized))

    def test_plain_sha256_metadata_is_not_mistaken_for_a_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "metadata.json").write_text(
                json.dumps({"sha256": "a" * 64}),
                encoding="utf-8",
            )

            findings, _ = scan(root, set(), check_git_history=False)

            self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
