---
title: Quickstart
description: Fastest path to running Argis locally through CLI or API, with first-run checks and common troubleshooting guidance.
---

# Quickstart

Use this page to get a local Argis environment running fast, then branch into CLI, API, or configuration-specific docs as needed.

## Prerequisites

- Python version supported by `pyproject.toml`
- `uv`
- a runtime profile you can actually execute:
  - local default: Ollama on `http://localhost:11434`
  - remote alternative: OpenAI-compatible profile with credentials

## Install

```bash
uv sync
```

Optional extras:

```bash
uv sync --extra api
uv sync --extra ui
uv sync --extra analysis
```

## Choose A Starting Path

### Fastest local path

Use the default Ollama-oriented profile if you already have a local model runtime:

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "Please verify your account now"
```

### OpenAI path

If you want remote judge-backed execution through the OpenAI profile:

```bash
export MY_AGENT_APP_PROFILE=openai
export OPENAI_API_KEY=your_key
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "Please verify your account now"
```

## Run CLI

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "Please verify your account now"
```

You can also start an interactive session:

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent
```

## Run API

```bash
PYTHONPATH=src uv run uvicorn phish_email_detection_agent.api.app:app --reload --host 0.0.0.0 --port 8000
```

Minimal request:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'content-type: application/json' \
  -d '{"text":"Please verify your account now"}'
```

## Quick Check

```bash
ruff check src tests docs scripts
pytest -k 'not hf_phishing_email_balanced_sample'
```

## What A Successful First Run Looks Like

For a basic CLI or API run, you should expect to see:

- a `verdict`, `risk_score`, and `confidence`
- `provider_used`, which tells you whether the final output used a configured remote provider or a deterministic fallback path
- `indicators` and `recommended_actions`

In API mode you should also see `runtime`, `skillpacks`, and `tools` summaries.

## Common First-Run Issues

### Remote model unavailable

If your provider is not reachable or not configured, Argis can still return deterministic fallback output. That is expected behavior, not necessarily a crash. In API responses this is visible through `provider_used` ending with `:fallback` and `fallback_reason` such as `remote_unavailable`.

### API input rejected

If the server returns HTTP `400`, treat it as a caller-input problem. Common cases are:

- `text` is not a string
- `eml_path` was sent to the API
- `attachments` are not object arrays with `name` or `filename`
- attachment identifiers look like filesystem paths

### Deep analysis did not run

Deep context is conditional. Even with capabilities enabled, the runtime only collects additional web or attachment context when the evidence stage decides that the score or signals justify it.

## Next Steps

- Use [CLI](/argis/using-argis/cli) for local triage and debugging.
- Use [App](/argis/using-argis/app) if you want an HTTP service.
- Use [Config File](/argis/configurations/config-file) to tune runtime behavior.
- Use [Runbook](/argis/operations/runbook) when moving into shared or production-like environments.
