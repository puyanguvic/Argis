#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="src:${PYTHONPATH:-}"
uv run pytest -q
