#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="src:${PYTHONPATH:-}"
uv run ruff check src tests examples
