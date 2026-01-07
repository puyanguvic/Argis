#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv not found. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  exit 1
fi

uv venv

if [[ "${1:-}" == "--no-local-llm" ]]; then
  uv pip install -e ".[ui]"
  echo "Installed core deps with UI extras, without local LLM extras."
else
  uv pip install -e ".[ui,local-llm]"
  echo "Installed core deps with UI and local LLM extras."
fi

echo "Run: python apps/gradio_demo/app.py"
