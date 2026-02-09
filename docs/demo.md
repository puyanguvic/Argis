# Demo Usage

## CLI

```bash
PYTHONPATH=src uv run python -m argis detect --input examples/email_sample.json
```

Replay:

```bash
PYTHONPATH=src uv run python -m argis replay --record run.jsonl
```

## Gradio

```bash
PYTHONPATH=src uv run python -m argis.ui.gradio_app
```

## Quick smoke test

```bash
./scripts/smoke_test.sh
```
