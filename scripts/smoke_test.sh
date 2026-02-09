#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="src:${PYTHONPATH:-}"
uv run pytest -q
uv run python -m argis detect --input examples/email_sample.json --format json > /tmp/argis-smoke.json
cat /tmp/argis-smoke.json | head -n 20
