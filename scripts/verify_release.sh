#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agent-tree-rl-release.XXXXXX")"
PYTHON="${PYTHON:-python3}"

cleanup() {
  rm -rf "$TEMP_ROOT" "$PROJECT_ROOT/agent_tree_rl.egg-info" "$PROJECT_ROOT/build"
}
trap cleanup EXIT

cd "$PROJECT_ROOT"
if ! "$PYTHON" -c "import build, ruff, setuptools, wheel" 2>/dev/null; then
  echo "release tooling is missing; install the pinned dev extra: pip install -e '.[dev]'" >&2
  exit 1
fi
"$PYTHON" -m ruff check --no-cache agent_tree_rl tests scripts examples
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m agent_tree_rl.cli verify
"$PYTHON" -m build --no-isolation --outdir "$TEMP_ROOT/dist"

WHEEL=("$TEMP_ROOT"/dist/agent_tree_rl-*.whl)
SDIST=("$TEMP_ROOT"/dist/agent_tree_rl-*.tar.gz)
if [[ ${#WHEEL[@]} -ne 1 || ! -f "${WHEEL[0]}" ]]; then
  echo "expected exactly one wheel" >&2
  exit 1
fi
if [[ ${#SDIST[@]} -ne 1 || ! -f "${SDIST[0]}" ]]; then
  echo "expected exactly one source distribution" >&2
  exit 1
fi

mkdir -p "$TEMP_ROOT/wheel-scan" "$TEMP_ROOT/sdist-scan"
"$PYTHON" -m zipfile -e "${WHEEL[0]}" "$TEMP_ROOT/wheel-scan"
"$PYTHON" -m tarfile --filter data -e "${SDIST[0]}" "$TEMP_ROOT/sdist-scan"
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" scripts/check_public_release.py \
  --root "$TEMP_ROOT/wheel-scan" \
  --skip-git-history
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" scripts/check_public_release.py \
  --root "$TEMP_ROOT/sdist-scan/agent_tree_rl-0.1.0" \
  --skip-git-history \
  --allow-sdist-metadata

"$PYTHON" -m pip wheel \
  "${SDIST[0]}" \
  --no-deps \
  --no-build-isolation \
  --wheel-dir "$TEMP_ROOT/sdist-wheel"

"$PYTHON" -m venv "$TEMP_ROOT/wheel-venv"
"$TEMP_ROOT/wheel-venv/bin/pip" install --no-deps "${WHEEL[0]}"
cd "$TEMP_ROOT"
PYTHONDONTWRITEBYTECODE=1 "$TEMP_ROOT/wheel-venv/bin/agent-tree-rl" verify
"$TEMP_ROOT/wheel-venv/bin/agent-tree-rl-evidence-probe" health

"$PYTHON" -m venv "$TEMP_ROOT/sdist-venv"
"$TEMP_ROOT/sdist-venv/bin/pip" install \
  --no-deps \
  "$TEMP_ROOT"/sdist-wheel/agent_tree_rl-*.whl
PYTHONDONTWRITEBYTECODE=1 "$TEMP_ROOT/sdist-venv/bin/agent-tree-rl" verify
"$TEMP_ROOT/sdist-venv/bin/agent-tree-rl-evidence-probe" health
