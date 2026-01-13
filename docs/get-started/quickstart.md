---
title: Quickstart
---

# Quickstart

Argis is designed to run offline/deterministically by default. Treat email content and headers as sensitive; avoid storing full bodies unless you need an audit trace (`--record`).

## 1) Install

From the repo root:

```
pip install -e .[test]
```

## 2) Run detection (sample input)

```
phish-agent detect --input examples/email_sample.json
```

The default output is a Markdown report printed to stdout.

## 3) Record + replay (audit-only)

```
phish-agent detect --input examples/email_sample.json --record run.jsonl
phish-agent replay --record run.jsonl
```

Only use `--record` when you explicitly need traceability/replay, because JSONL records may contain sensitive evidence.

## 4) Optional: launch the Gradio demo

```
python apps/demo/gradio_app.py
```

Next: [Using Argis](../using-argis/index.md).
