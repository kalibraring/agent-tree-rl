#!/usr/bin/env python3
"""Fail closed on common public-release leaks and broken documentation links.

The scanner uses only the Python standard library and walks the candidate
directory directly. It therefore works before ``git init`` and also catches
untracked files after initialization. When a local ``.git`` directory exists,
it additionally checks commit author and committer email addresses.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote, urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAX_PUBLIC_FILE_BYTES = 5 * 1024 * 1024

IGNORED_DIRECTORIES = {".git"}
FORBIDDEN_DIRECTORIES = {
    ".eggs",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "backups",
    "build",
    "coverage",
    "data",
    "deploy-secrets",
    "dist",
    "htmlcov",
    "internal",
    "node_modules",
    "private",
    "secrets",
    "var",
    "venv",
}
FORBIDDEN_EXACT_FILES = {
    ".coverage",
    ".env",
    ".python-version.local",
    "api-tokens.json",
    "backup-keys.json",
    "benchmark-signing.key",
    "bootstrap-tokens.json",
    "policy-benchmark.json",
    "receipt-keys.json",
}
FORBIDDEN_SUFFIXES = {
    ".atrlb",
    ".bak",
    ".crt",
    ".db",
    ".jks",
    ".key",
    ".keystore",
    ".log",
    ".orig",
    ".p12",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".swp",
    ".whl",
    ".zip",
}
ARCHIVE_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz")
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9._%+-])"
)
DEFAULT_ALLOWED_EMAIL_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "users.noreply.github.com",
}
DEFAULT_ALLOWED_EMAILS = {"noreply@github.com"}

MACHINE_PATH_RULES = (
    (
        "mac-home-path",
        re.compile(re.escape("/" + "Users/") + r"[^/\s]+/"),
        "contains a macOS user-home path",
    ),
    (
        "linux-home-path",
        re.compile(re.escape("/" + "home/") + r"[^/\s]+/"),
        "contains a Linux user-home path",
    ),
    (
        "windows-home-path",
        re.compile(r"[A-Za-z]:\\" + re.escape("Users\\") + r"[^\\\s]+\\"),
        "contains a Windows user-home path",
    ),
    (
        "mac-temp-path",
        re.compile(re.escape("/" + "private/var/folders/") + r"[^\s]+"),
        "contains a machine-specific macOS temporary path",
    ),
)

# Split signature literals so this scanner does not flag its own source file.
CREDENTIAL_RULES = (
    (
        "private-key",
        re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH |DSA )?" + "PRIVATE KEY-----"),
        "contains a private-key header",
    ),
    (
        "github-token",
        re.compile(r"(?:gh" + r"[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        "contains a GitHub credential signature",
    ),
    (
        "aws-access-key",
        re.compile(r"(?:AK" + r"IA|ASIA)[0-9A-Z]{16}"),
        "contains an AWS access-key signature",
    ),
    (
        "openai-key",
        re.compile(r"sk-" + r"(?:proj-)?[A-Za-z0-9_-]{32,}"),
        "contains an OpenAI-style credential signature",
    ),
    (
        "anthropic-key",
        re.compile(r"sk-ant-" + r"[A-Za-z0-9_-]{24,}"),
        "contains an Anthropic credential signature",
    ),
    (
        "google-api-key",
        re.compile(r"AI" + r"za[0-9A-Za-z_-]{35}"),
        "contains a Google API-key signature",
    ),
    (
        "slack-token",
        re.compile(r"xox" + r"[abprs]-[A-Za-z0-9-]{20,}"),
        "contains a Slack credential signature",
    ),
    (
        "stripe-live-key",
        re.compile(r"(?:sk|rk)_" + r"live_[A-Za-z0-9]{20,}"),
        "contains a Stripe live credential signature",
    ),
    (
        "jwt-bearer",
        re.compile(r"Bearer\s+eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "contains a bearer JWT",
    ),
    (
        "credential-url",
        re.compile(r"https?://[^\s/:@]+:[^\s/@]+@[^\s/]+"),
        "contains credentials embedded in a URL",
    ),
)

BOOTSTRAP_TOKEN_JSON_RE = re.compile(
    r'"api_tokens"\s*:\s*\{.{0,8192}?'
    r'"(?:agent|operator|promoter|auditor)"\s*:\s*'
    r'"[A-Za-z0-9_-]{60,}"',
    re.DOTALL,
)

INLINE_MARKDOWN_LINK_RE = re.compile(
    r"!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))"
)
REFERENCE_MARKDOWN_LINK_RE = re.compile(
    r"^\s{0,3}\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))"
)
MARKDOWN_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str

    def render(self) -> str:
        location = self.path if self.line <= 0 else f"{self.path}:{self.line}"
        return f"{location}: [{self.rule}] {self.message}"


@dataclass
class ScanStats:
    files: int = 0
    markdown_links: int = 0


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _email_is_allowed(email: str, allowed_emails: set[str]) -> bool:
    normalized = email.lower()
    if normalized in allowed_emails or normalized in DEFAULT_ALLOWED_EMAILS:
        return True
    domain = normalized.rsplit("@", 1)[-1]
    return domain in DEFAULT_ALLOWED_EMAIL_DOMAINS


def _path_findings(path: Path, root: Path) -> list[Finding]:
    rel = _relative(path, root)
    name = path.name
    lowered = name.lower()
    findings: list[Finding] = []

    if lowered.startswith(".env") and lowered != ".env.example":
        findings.append(Finding(rel, 0, "environment-file", "remove the environment file"))
    if lowered in FORBIDDEN_EXACT_FILES:
        findings.append(Finding(rel, 0, "sensitive-file", "remove generated or sensitive state"))
    if any(lowered.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        findings.append(Finding(rel, 0, "sensitive-suffix", "remove generated or sensitive file type"))
    if lowered.endswith(ARCHIVE_SUFFIXES):
        findings.append(Finding(rel, 0, "generated-archive", "remove generated release archives"))
    if lowered.endswith(".egg-info"):
        findings.append(Finding(rel, 0, "generated-package", "remove generated package metadata"))
    if path.is_file() and path.stat().st_size > MAX_PUBLIC_FILE_BYTES:
        findings.append(
            Finding(
                rel,
                0,
                "large-file",
                f"file is larger than {MAX_PUBLIC_FILE_BYTES} bytes; review or use release assets",
            )
        )
    return findings


def _read_text(path: Path) -> str | None:
    with path.open("rb") as handle:
        data = handle.read(MAX_PUBLIC_FILE_BYTES + 1)
    if len(data) > MAX_PUBLIC_FILE_BYTES:
        return None
    # Decode every bounded file regardless of its suffix. This deliberately
    # inspects ASCII/UTF-8 strings embedded in binary-looking files so a custom
    # bootstrap-token destination cannot evade the scanner by being named .png.
    return data.decode("utf-8", errors="ignore")


def _content_findings(
    path: Path,
    root: Path,
    text: str,
    allowed_emails: set[str],
) -> list[Finding]:
    rel = _relative(path, root)
    findings: list[Finding] = []
    bootstrap_token = BOOTSTRAP_TOKEN_JSON_RE.search(text)
    if bootstrap_token is not None:
        findings.append(
            Finding(
                rel,
                text.count("\n", 0, bootstrap_token.start()) + 1,
                "bootstrap-bearer-token",
                "contains plaintext Agent Tree RL bootstrap credentials",
            )
        )
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern, message in MACHINE_PATH_RULES:
            if pattern.search(line):
                findings.append(Finding(rel, line_number, rule, message))
        for rule, pattern, message in CREDENTIAL_RULES:
            if pattern.search(line):
                findings.append(Finding(rel, line_number, rule, message))
        for match in EMAIL_RE.finditer(line):
            email = match.group(0)
            if not _email_is_allowed(email, allowed_emails):
                findings.append(
                    Finding(
                        rel,
                        line_number,
                        "email-address",
                        f"remove or explicitly allow public email address {email!r}",
                    )
                )
    return findings


def _markdown_lines(text: str) -> list[tuple[int, str]]:
    visible: list[tuple[int, str]] = []
    fence: str | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        marker = stripped[:3]
        if marker in {"```", "~~~"}:
            if fence is None:
                fence = marker
            elif marker == fence:
                fence = None
            continue
        if fence is None:
            visible.append((line_number, line))
    return visible


def _markdown_targets(text: str) -> list[tuple[int, str]]:
    targets: list[tuple[int, str]] = []
    for line_number, line in _markdown_lines(text):
        for match in INLINE_MARKDOWN_LINK_RE.finditer(line):
            targets.append((line_number, match.group(1) or match.group(2)))
        reference = REFERENCE_MARKDOWN_LINK_RE.match(line)
        if reference:
            targets.append((line_number, reference.group(1) or reference.group(2)))
    return targets


def _github_heading_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    duplicates: dict[str, int] = {}
    for _, line in _markdown_lines(text):
        match = MARKDOWN_HEADING_RE.match(line)
        if not match:
            continue
        heading = re.sub(r"<[^>]+>", "", match.group(1))
        heading = re.sub(r"[`*_~]", "", heading)
        heading = unicodedata.normalize("NFKC", heading).strip().lower()
        heading = "".join(
            character
            for character in heading
            if character.isalnum() or character in {" ", "-", "_"}
        )
        base = re.sub(r"\s+", "-", heading)
        duplicate = duplicates.get(base, 0)
        anchor = base if duplicate == 0 else f"{base}-{duplicate}"
        duplicates[base] = duplicate + 1
        anchors.add(anchor)
    return anchors


def _has_exact_case(root: Path, relative: Path) -> bool:
    current = root
    for part in relative.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            current = current.parent
            continue
        try:
            names = {child.name for child in current.iterdir()}
        except OSError:
            return False
        if part not in names:
            return False
        current /= part
    return True


def _markdown_link_findings(
    markdown: Path,
    root: Path,
    text: str,
    stats: ScanStats,
) -> list[Finding]:
    findings: list[Finding] = []
    rel = _relative(markdown, root)
    root_resolved = root.resolve()
    for line_number, raw_target in _markdown_targets(text):
        target = raw_target.strip()
        if not target or target.startswith(("#", "//")):
            path_part = ""
            fragment = unquote(target[1:]) if target.startswith("#") else ""
        else:
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            path_part = unquote(parsed.path)
            fragment = unquote(parsed.fragment)
        stats.markdown_links += 1

        candidate = markdown if not path_part else (
            root / path_part.lstrip("/")
            if path_part.startswith("/")
            else markdown.parent / path_part
        )
        normalized = Path(os.path.normpath(candidate))
        resolved = normalized.resolve(strict=False)
        try:
            root_relative = resolved.relative_to(root_resolved)
        except ValueError:
            findings.append(
                Finding(rel, line_number, "markdown-link", f"local link escapes repository: {target}")
            )
            continue

        if not resolved.exists() or not _has_exact_case(root_resolved, root_relative):
            findings.append(
                Finding(rel, line_number, "markdown-link", f"broken local link: {target}")
            )
            continue
        if fragment and resolved.is_file() and resolved.suffix.lower() == ".md":
            try:
                target_text = _read_text(resolved)
            except OSError as error:
                findings.append(
                    Finding(
                        rel,
                        line_number,
                        "markdown-link",
                        f"could not read local link target {target}: {error}",
                    )
                )
                continue
            if target_text is not None and fragment.lower() not in _github_heading_anchors(target_text):
                findings.append(
                    Finding(rel, line_number, "markdown-anchor", f"missing Markdown anchor: {target}")
                )
    return findings


def _git_history_findings(root: Path, allowed_emails: set[str]) -> list[Finding]:
    if not (root / ".git").exists():
        return []
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(root),
                "log",
                "--all",
                "--format=%H%x09%ae%x09%ce",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return [Finding(".git", 0, "git-history", f"could not inspect commit metadata: {error}")]
    if result.returncode != 0:
        detail = result.stderr.strip() or "git log failed"
        return [Finding(".git", 0, "git-history", detail)]

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for record in result.stdout.splitlines():
        commit, author_email, committer_email = (record.split("\t") + ["", ""])[:3]
        for role, email in (("author", author_email), ("committer", committer_email)):
            normalized = email.lower()
            if not email or _email_is_allowed(email, allowed_emails):
                continue
            key = (role, normalized)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    ".git-history",
                    0,
                    "commit-email",
                    f"{role} email {email!r} appears in commit {commit[:12]}",
                )
            )
    return findings


def _ignore_coverage_findings(root: Path) -> list[Finding]:
    """Require Docker build context exclusions to cover repository runtime ignores."""

    gitignore = root / ".gitignore"
    dockerignore = root / ".dockerignore"
    if not (root / "deploy" / "Dockerfile").exists():
        return []
    missing_files = [
        path.name for path in (gitignore, dockerignore) if not path.is_file()
    ]
    if missing_files:
        return [
            Finding(
                ".",
                0,
                "ignore-coverage",
                "container project is missing " + ", ".join(sorted(missing_files)),
            )
        ]

    def patterns(path: Path) -> set[str]:
        result: set[str] = set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            value = raw.strip()
            if not value or value.startswith(("#", "!")):
                continue
            result.add(value.rstrip("/"))
        return result

    uncovered = sorted(patterns(gitignore).difference(patterns(dockerignore)))
    if not uncovered:
        return []
    return [
        Finding(
            ".dockerignore",
            0,
            "ignore-coverage",
            "Docker build context does not exclude: " + ", ".join(uncovered),
        )
    ]


def scan(
    root: Path,
    allowed_emails: set[str],
    check_git_history: bool,
    *,
    allow_sdist_metadata: bool = False,
) -> tuple[list[Finding], ScanStats]:
    root = root.resolve()
    findings: list[Finding] = []
    stats = ScanStats()

    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            child = current / name
            if name in IGNORED_DIRECTORIES:
                continue
            lowered = name.lower()
            expected_sdist_metadata = (
                allow_sdist_metadata
                and current == root
                and name == "agent_tree_rl.egg-info"
            )
            if lowered in FORBIDDEN_DIRECTORIES or (
                lowered.endswith(".egg-info") and not expected_sdist_metadata
            ):
                findings.append(
                    Finding(
                        _relative(child, root),
                        0,
                        "generated-directory",
                        "remove generated, private, or runtime directory",
                    )
                )
                continue
            if child.is_symlink():
                target = child.resolve(strict=False)
                if not target.exists() or not target.is_relative_to(root):
                    findings.append(
                        Finding(_relative(child, root), 0, "unsafe-symlink", "symlink is broken or escapes repository")
                    )
                continue
            kept_directories.append(name)
        directory_names[:] = kept_directories

        for name in sorted(file_names):
            path = current / name
            stats.files += 1
            if path.is_symlink():
                target = path.resolve(strict=False)
                if not target.exists() or not target.is_relative_to(root):
                    findings.append(
                        Finding(_relative(path, root), 0, "unsafe-symlink", "symlink is broken or escapes repository")
                    )
                continue
            findings.extend(_path_findings(path, root))
            try:
                text = _read_text(path)
            except OSError as error:
                findings.append(
                    Finding(
                        _relative(path, root),
                        0,
                        "unreadable-file",
                        f"could not inspect file: {error}",
                    )
                )
                continue
            if text is None:
                continue
            findings.extend(_content_findings(path, root, text, allowed_emails))
            if path.suffix.lower() == ".md":
                findings.extend(_markdown_link_findings(path, root, text, stats))

    if check_git_history:
        findings.extend(_git_history_findings(root, allowed_emails))
    findings.extend(_ignore_coverage_findings(root))
    return sorted(set(findings)), stats


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="candidate repository root (defaults to this script's project)",
    )
    parser.add_argument(
        "--allow-email",
        action="append",
        default=[],
        metavar="ADDRESS",
        help="allow an intentional public email address; may be repeated",
    )
    parser.add_argument(
        "--skip-git-history",
        action="store_true",
        help="skip commit email inspection when .git exists",
    )
    parser.add_argument(
        "--allow-sdist-metadata",
        action="store_true",
        help="allow and inspect the standard top-level agent_tree_rl.egg-info directory",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"public release check failed: root is not a directory: {root}", file=sys.stderr)
        return 2
    allowed_emails = {email.lower() for email in args.allow_email}
    findings, stats = scan(
        root,
        allowed_emails,
        not args.skip_git_history,
        allow_sdist_metadata=args.allow_sdist_metadata,
    )
    if findings:
        print(f"public release check failed with {len(findings)} finding(s):", file=sys.stderr)
        for finding in findings:
            print(f"  {finding.render()}", file=sys.stderr)
        return 1
    print(
        "public release check passed: "
        f"{stats.files} files and {stats.markdown_links} local Markdown links checked"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
