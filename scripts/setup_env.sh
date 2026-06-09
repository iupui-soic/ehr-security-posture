#!/usr/bin/env bash
# Create an isolated Python 3.11 venv for this project and install pinned deps.
# Safe to re-run. Uses uv to fetch a standalone CPython 3.11 (no system change).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"

echo "[setup] fetching CPython 3.11 via uv ..."
uv python install 3.11

echo "[setup] creating .venv (python 3.11) ..."
uv venv --python 3.11 .venv

echo "[setup] installing pinned project deps ..."
# Use uv pip into the project venv; -e . pulls deps from pyproject.toml.
VIRTUAL_ENV="$(pwd)/.venv" uv pip install -e ".[dev]"

echo "[setup] freezing exact versions -> requirements.lock ..."
VIRTUAL_ENV="$(pwd)/.venv" uv pip freeze > requirements.lock

echo "[setup] python: $(.venv/bin/python --version)"
echo "[setup] DONE"
