---
layout: default
title: Problem Statement
---

# Problem statement and threat context

## What we are solving

Phishing and related email-based social engineering (BEC, OAuth consent abuse, malicious attachments) share common traits:

- **Low cost, high volume**: attackers ship variants fast and evade static rules.
- **Context dependent**: “abnormal” depends on org relationships, workflows, and user context.
- **Distributed signals**: risk signals live across headers, domains/URLs, content intent, and attachments.
- **High cost of errors**: false positives interrupt business; false negatives cause credential theft or loss.

The goal is not “a single model makes the decision,” but an **evidence-first** agent that collects structured signals, quantifies risk, and outputs an auditable result for each email.

## Inputs and outputs (system boundary)

### Input (`EmailInput`)

The minimum input is a normalized `EmailInput` (see `schemas/email_schema.py`) containing:

- `raw_headers`: raw headers (used for SPF/DKIM/DMARC extraction)
- `subject` / `sender` / `reply_to`
- `body_text` / `body_html`
- `urls` (optional; extracted from body if empty)
- `attachments`: attachment metadata (static analysis only; no execution)
- `received_ts`

### Output (`DetectionResult`)

The system emits a `DetectionResult` (see `engine/state.py`) with:

- `verdict`: `benign` / `suspicious` / `phishing`
- `risk_score`: 0–100
- `evidence`: `EvidenceStore` (see `schemas/evidence_schema.py`)
- `explanation`: structured explanation (see `schemas/explanation_schema.py`)
- `trace_id`: traceable identifier (hash of input fields)

## Constraints and assumptions

- **Offline by default**: URL parsing and domain risk use deterministic, offline tooling (examples in `tools_builtin/`).
- **Auditable evidence**: tool outputs are aggregated into `EvidenceStore`; JSONL recording and replay enable audit (`engine/recorder.py`, `engine/player.py`).
- **No chain-of-thought**: explanations reference evidence keys and score breakdowns, not model reasoning (`engine/explanation.py`).

## Glossary

- **Evidence**: structured tool outputs (header auth, URL chain, domain risk, semantic intent, attachment scan).
- **Hard rules**: combinations that force `phishing` (`scoring/rules.py`).
- **Risk fusion**: weighted aggregation into a 0–100 score (`scoring/fusion.py`).
