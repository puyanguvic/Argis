#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="src:${PYTHONPATH:-}"
uv run python -m argis detect --input examples/email_sample.json
