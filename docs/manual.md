# Argis Manual

Status: Living document
Last updated: 2026-02-25

[[_TOC_]]

## Overview

Argis is a phishing email detection agent stack with a deterministic-first kernel and an optional model judge.

This manual focuses on how to run, configure, and operate the system. For architecture and design rationale, see
`docs/design.md`.

## Quickstart

### Prerequisites

- Python (see `pyproject.toml` for the minimum supported version).
- `uv` for dependency management.
- Optional:
  - Ollama (recommended local model runtime).
  - URL fetch sandbox backends: `firejail` and/or `docker` if you choose those backends.

### Install

```bash
uv sync
```

Optional extras:

```bash
uv sync --extra api   # FastAPI + uvicorn
uv sync --extra ui    # Gradio UI
uv sync --extra analysis  # OCR / audio transcription dependencies
```

### Run (CLI)

Interactive chat:

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent
```

Single input:

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "Please verify your account now"
```

Model override:

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --model ollama/qwen2.5:7b --text "review this email"
```

Tip: there is also a console script entrypoint:

```bash
PYTHONPATH=src uv run phish-email-detection-agent --text "test message"
```

## Input formats

Argis accepts either plain text or a JSON-encoded payload passed via `--text`.

Plain text:

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "Urgent: reset your password now"
```

Structured JSON (text + URLs + attachments):

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text '{"text":"Urgent: login now","urls":["https://bit.ly/reset"],"attachments":["invoice.zip"]}'
```

EML input:

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text '{"eml_path":"/path/to/sample.eml"}'
```

## Configuration

Configuration is loaded from YAML defaults and environment variables:

- Defaults: `src/phish_email_detection_agent/config/defaults.yaml`
- Loader: `src/phish_email_detection_agent/config/settings.py::load_config`
- Example env file: `.env.example`

### Common environment switches

Provider/profile selection:

- `MY_AGENT_APP_PROFILE`: selects a runtime profile (for example `openai` or `ollama`).
- `OPENAI_API_KEY`: required for OpenAI provider usage.

Deep analysis and side effects:

- `MY_AGENT_APP_ENABLE_DEEP_ANALYSIS=true`: one-switch enablement for URL fetch + OCR + audio transcription (unless overridden).
- `MY_AGENT_APP_ENABLE_URL_FETCH=true`: enable safe URL fetch.
- `MY_AGENT_APP_ALLOW_PRIVATE_NETWORK=true`: allow private-network access (default is blocked; use with extreme caution).

URL fetch limits and sandboxing:

- `MY_AGENT_APP_FETCH_TIMEOUT_S`
- `MY_AGENT_APP_FETCH_MAX_REDIRECTS`
- `MY_AGENT_APP_FETCH_MAX_BYTES`
- `MY_AGENT_APP_URL_FETCH_BACKEND=internal|firejail|docker`

Notes:

- Safe fetch blocks executable-style binary downloads (e.g., `application/octet-stream`) with `blocked_reason=binary_download_blocked`.
- Even when deep analysis is enabled, all side effects remain bounded by explicit limits.

## API (optional)

Install API dependencies:

```bash
uv sync --extra api
```

Run the server:

```bash
PYTHONPATH=src uv run uvicorn phish_email_detection_agent.api.app:app --reload --host 0.0.0.0 --port 8000
```

Endpoints:

- `GET /health`
- `POST /analyze` (payload: `{ "text": "...", "model": "optional" }`)

## UI / HF Space (optional)

Install UI dependencies:

```bash
uv sync --extra ui
```

Hugging Face Space entrypoint:

- `src/phish_email_detection_agent/ui/gradio_app.py`

## Local development

Typical local loop:

```bash
uv sync
PYTHONPATH=src uv run python -m phish_email_detection_agent
```

Recommended local model path (Ollama):

```bash
ollama pull qwen2.5:7b
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "test message"
```

## Testing

Fast local cycle:

```bash
ruff check src tests docs scripts
pytest -k 'not hf_phishing_email_balanced_sample'
```

Targeted suites:

```bash
pytest tests/policy tests/orchestrator
pytest tests/api tests/domain tests/tools
```

Evaluation (slower; use as a regression checkpoint):

```bash
pytest tests/evaluation/test_hf_eval_balanced_sample.py
```

