---
title: Argis Phish Email Detection
sdk: gradio
app_file: apps/demo/gradio_app.py
python_version: "3.10"
---


# Argis: Phish Email Detection Agent

A minimal, deterministic phishing detection agent built around evidence-first design. The system collects structured evidence, quantifies risk, fuses evidence with policy rules, and only then produces a verdict. Models (if added later) are just evidence sources, never the final judge.

## Evidence-centric behavior

- Plan (router) chooses FAST, STANDARD, or DEEP from quick features + header auth checks and returns a structured execution plan.
- Agent (tools) executes deterministic tools to convert raw inputs into structured evidence.
- Policy fuses hard rules + soft scores to produce a verdict and recommended action.
- All tool outputs live in a single `EvidenceStore` (Pydantic model).
- Explanations cite evidence keys and include a score breakdown (no chain-of-thought).

## Contextual escalation signals

Some collaboration/OAuth workflows are low-noise and do not trip classic hard signals. The agent therefore includes contextual escalation signals that *only* route FAST → STANDARD for deeper evidence collection (URL analysis, domain risk checks) without adding risk points by themselves. These are non-risk triggers tied to semantic intent + collaboration brands/keywords and external/untrusted senders.

## Layered reasoning

- Plan (orchestration): decides what to check, tool set, budget, timeouts, and fallback.
- Agent (tools): each tool converts raw input into structured evidence.
- Policy (fusion): hard rules + soft scores produce allow/warn/quarantine.

## Project layout

```
phish-agent/
├── src/argis/               # App package (core/llm/agents/tools/runtime/ui)
├── protocol/                # Stable UI <-> Engine contract (Op/Event)
├── engine/                  # Core engine (session/task/turn + detection pipeline)
├── tools_builtin/           # Deterministic evidence tools (offline by default)
├── providers/               # Model adapters (Ollama, etc.)
├── connectors/              # Gmail/IMAP connectors (pluggable)
├── apps/                    # Backward-compatible entry points
├── schemas/                 # Input/decision schemas (Pydantic)
├── scoring/                 # Fusion + hard rules
├── configs/                 # Profiles + provider/connector configs/prompts
├── scripts/                 # Local run + smoke scripts
├── docs/                    # Architecture + protocol docs
├── examples/                # Sample inputs
└── tests/                   # Unit tests
```

Protocol details: `docs/get-started/concepts/protocol/v1.md`.

## Quick start

1) Install dependencies:

```
pip install -e .[test]
```

2) Run detection with the sample input (default report output):

```
phish-agent detect --input examples/email_sample.json --record run.jsonl
# or the new app package entrypoint:
PYTHONPATH=src python -m argis detect --input examples/email_sample.json --record run.jsonl
```

3) Replay a recorded run (audit-only, no tools):

```
phish-agent replay --record run.jsonl
```

4) Run tests:

```
pytest
```

5) Optional: launch the Gradio demo:

```
python apps/demo/gradio_app.py
```

## EmailInput schema

See `schemas/email_schema.py`. Minimum fields:

- `raw_headers` (string)
- `subject`, `sender`, `reply_to`
- `body_text` / `body_html`
- `urls` (optional, auto-extracted if empty)
- `attachments` (list of `AttachmentMeta`)
- `received_ts` (datetime ISO-8601)

## Plan output

Plan output is stored under `EvidenceStore.plan` and includes:

- `path`: FAST / STANDARD / DEEP
- `tools`: ordered tool list
- `budget_ms`, `timeout_s`
- `fallback`

This plan is recorded to JSONL when `--record` is enabled.

## Configuration

App-level selectors (profile/provider/connector) live in `configs/app.yaml`.
Tune routing thresholds and scoring weights in `configs/profiles/balanced.yaml`.
Legacy config fallback remains in `configs/default.yaml`.
Contextual escalation signals (brands, intents, keywords) and allowlisted domains also live in the profile config.

## How to add real tool backends

Default tools are deterministic and offline by design. To add real integrations:

1) Implement a backend that returns the same result models (e.g., `HeaderAuthResult`).
2) Swap the function used in `engine/orchestrator.py` for your backend call.
3) Keep the output schema stable so scoring and explanations remain unchanged.

## CLI output format

Default output is a Markdown report. Use `--format json` for structured output.

Example report:

```
# Phishing Detection Report

**Verdict:** QUARANTINE (HIGH, score 82/100)
**Confidence:** HIGH
**Trace ID:** phish-20260107-8f3c2d
**Profile:** STANDARD
```

JSON output example:

```
{
  "verdict": "phishing",
  "risk_score": 82,
  "explanation": {
    "verdict": "...",
    "risk_score": 82,
    "top_signals": ["score_factor:spf_fail", "..."],
    "recommended_action": "quarantine",
    "evidence": {...},
    "score_breakdown": [...]
  }
}
```

## License

TBD
