---
layout: default
title: CLI
---

# CLI

The CLI is the simplest way to run detection over a JSON input (`EmailInput`).

## Commands

- `detect`: run a detection turn on an input JSON payload.
- `replay`: recompute a verdict from a recorded JSONL trace (no tool execution).

## Detect

```
phish-agent detect --input examples/email_sample.json
```

Options:

- `--format report|json`: choose Markdown report (default) or JSON output.
- `--record run.jsonl`: write a JSONL trace for audit/replay (sensitive).

## Output formats

- Default: human-readable Markdown report
- JSON: `--format json`

## Audit recording

Use `--record` to write a JSONL trace, then replay it without re-running tools:

```
phish-agent detect --input examples/email_sample.json --record run.jsonl
phish-agent replay --record run.jsonl
```

## Connector inputs

The engine supports `input_kind: "connector"` (fetch message by `message_id`), but the CLI currently accepts JSON input only. See `using-argis/connectors/index.md` for current connector status.
