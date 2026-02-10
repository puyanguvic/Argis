#!/usr/bin/env bash
set -euo pipefail

uv run python -m phish_email_detection_agent "$@"
