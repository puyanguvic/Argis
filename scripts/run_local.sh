#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="src:${PYTHONPATH:-}"
uv run python -m phish_email_detection_agent.ui.gradio_app
