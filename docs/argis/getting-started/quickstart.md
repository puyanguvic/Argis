# Quickstart

Use this page to get a local Argis environment running fast, then branch into CLI, API, or configuration-specific docs as needed.

## Prerequisites

- Python version supported by `pyproject.toml`
- `uv`

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

## Run CLI

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "Please verify your account now"
```

## Run API

```bash
PYTHONPATH=src uv run uvicorn phish_email_detection_agent.api.app:app --reload --host 0.0.0.0 --port 8000
```

## Quick Check

```bash
ruff check src tests docs scripts
pytest -k 'not hf_phishing_email_balanced_sample'
```

## Next Steps

- Use [CLI](/argis/using-argis/cli) for local triage and debugging.
- Use [App](/argis/using-argis/app) if you want an HTTP service.
- Use [Config File](/argis/configurations/config-file) to tune runtime behavior.
- Use [Runbook](/argis/operations/runbook) when moving into shared or production-like environments.
