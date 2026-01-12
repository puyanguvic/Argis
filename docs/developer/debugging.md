---
layout: default
title: Debugging and Trace
---

# Debugging and trace

The system supports **record and replay** for reproducible debugging and regression comparisons.

## 1) Quick debug: CLI + JSON input

```bash
phish-agent detect --input examples/email_sample.json
```

## 2) Record execution trace (JSONL)

```bash
phish-agent detect --input examples/email_sample.json --record run.jsonl
```

Inspect `run.jsonl` by `node_name` to locate which step produced evidence.

## 3) Replay (no tool execution)

```bash
phish-agent replay --record run.jsonl
```

Replay will:

- merge JSONL tool outputs into `EvidenceStore`
- recompute verdict/score using current config (`engine/player.py`)

Use cases:

- compare decisions across config/rule versions
- reproduce bugs without external dependencies

## 4) Tests

```bash
pytest
```

When changing weights or rules, update tests to prevent regressions.
