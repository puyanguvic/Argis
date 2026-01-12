---
layout: default
title: Reasoning Policy and Guardrails
---

# Reasoning policy and guardrails

This page defines constraints on reasoning and outputs to keep the system safe, controllable, and auditable.

## 1) Evidence constraints

- Decisions must be derived from `EvidenceStore` only.
- Every risk factor must trace to:
  - a concrete tool output field (e.g., `header_auth.dmarc`), or
  - a hard-rule match code (`scoring/rules.py`).
- Explanations reference evidence keys and structured content only (no full email bodies).

## 2) Output constraints

- No chain-of-thought: rely on `top_signals` and `score_breakdown` (`schemas/explanation_schema.py`).
- Recommended actions are fixed to `allow / warn / quarantine` (`engine/explanation.py`).
- Human reports avoid excessive technical detail while retaining auditable evidence IDs (`engine/report.py`).

## 3) Tool safety constraints

- Offline and deterministic by default to avoid upstream volatility.
- Tool outputs must be serializable for reliable JSONL record/replay (`engine/recorder.py`).
- Tool errors should be recorded as degradations or missing evidence (suggest `evidence.degradations`).

## 4) Risk control (avoid over/under-calling)

- For low-evidence cases, prefer `suspicious` with escalation rather than forcing `phishing`.
- For collaboration/OAuth low-noise cases, use contextual escalation to gather more evidence without direct scoring.
- Lock behavior through configuration and tests: thresholds/weights are configurable and should be regression-tested (`tests/`).
