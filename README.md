# Phish Email Detection Agent

A minimal, deterministic phishing detection agent built around evidence-first design. The system collects structured evidence, quantifies risk, fuses evidence with policy rules, and only then produces a verdict. Models (if added later) are just evidence sources, never the final judge.

## Evidence-centric behavior

- Plan (router) chooses FAST, STANDARD, or DEEP from quick features + header auth checks and returns a structured execution plan.
- Agent (tools) executes deterministic tools to convert raw inputs into structured evidence.
- Policy fuses hard rules + soft scores to produce a verdict and recommended action.
- All tool outputs live in a single `EvidenceStore` (Pydantic model).
- Explanations cite evidence keys and include a score breakdown (no chain-of-thought).

## Layered reasoning

- Plan (orchestration): decides what to check, tool set, budget, timeouts, and fallback.
- Agent (tools): each tool converts raw input into structured evidence.
- Policy (fusion): hard rules + soft scores produce allow/warn/quarantine.

## Project layout

```
phish-agent/
├── agent/
│   ├── cli.py               # CLI entrypoints
│   ├── config.py            # Router + scoring config
│   ├── explanation.py       # Structured explanation
│   ├── orchestrator.py      # Plan + tool execution runner
│   ├── policy.py            # Hard rules + fusion policy
│   ├── player.py            # Replay from JSONL
│   ├── recorder.py          # Audit log recorder
│   └── router.py            # FAST/STANDARD/DEEP routing
│
├── schemas/
│   ├── email_schema.py      # EmailInput + AttachmentMeta
│   ├── evidence_schema.py   # EvidenceStore + tool results
│   └── explanation_schema.py
│
├── scoring/
│   ├── fusion.py            # Weighted score fusion
│   └── rules.py             # Hard rule triggers
│
├── tools/
│   ├── header_analyzer.py   # SPF/DKIM/DMARC parsing
│   ├── url_analyzer.py      # URL chain + lexical checks
│   ├── domain_risk.py       # Lookalike detection
│   ├── content_analyzer.py  # Semantic extraction
│   ├── attachment_analyzer.py
│   └── parser.py            # Raw email -> EmailInput
│
├── configs/
│   └── default.yaml         # Router + scoring weights
│
├── examples/
│   └── email_sample.json    # Sample EmailInput payload
│
└── tests/
    ├── test_router.py
    ├── test_scoring.py
    └── test_explain.py
```

## Quick start

1) Install dependencies:

```
pip install -e .[test]
```

2) Run detection with the sample input (default report output):

```
phish-agent detect --input examples/email_sample.json --record run.jsonl
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
python apps/gradio_demo/app.py
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

Tune routing thresholds and scoring weights in `configs/default.yaml`.

## How to add real tool backends

Default tools are deterministic and offline by design. To add real integrations:

1) Implement a backend that returns the same result models (e.g., `HeaderAuthResult`).
2) Swap the function used in `agent/orchestrator.py` for your backend call.
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
