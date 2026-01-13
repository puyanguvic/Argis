---
layout: default
title: Decision Logic and Risk Scoring
redirect_from:
  - /agent/decision-logic.html
---

# Decision logic and risk scoring

This page explains how verdicts are produced from evidence. Core idea: **route first, then collect evidence; evidence first, then decide**.

## 1) Routing (FAST / STANDARD / DEEP)

Routing logic lives in `engine/router.py`:

1. Compute `QuickFeatures`:
   - `from_domain_mismatch`
   - `reply_to_mismatch`
   - `has_urls`
   - `suspicious_subject`
2. Parse `HeaderAuthResult` (SPF/DKIM/DMARC + alignment)
3. Merge into a `preliminary_score` (0–100)
4. Pick a path:
   - `< t_fast` → `FAST`
   - `>= t_deep` → `DEEP`
   - else → `STANDARD`

Default thresholds and tool sets are in `configs/profiles/balanced.yaml`.

## 2) Contextual escalation (FAST → STANDARD)

Triggered when all of the following are true (`engine/orchestrator.py`):

- Current path is `FAST`
- Sender domain is not in allowlist (`AgentConfig.allowlist_domains`)
- `semantic.intent` matches `contextual_escalation.intents`
- `semantic.brand_entities` intersects `contextual_escalation.brands`, or body matches `contextual_escalation.keywords`

Effect:

- Escalates investigation depth only (runs STANDARD tools, usually URL analysis)
- Does **not** directly add risk score

## 3) Verdict (hard rules + risk fusion)

Entry point: `engine/policy.py`.

### 3.1 Hard rules

Implementation: `scoring/rules.py`.

- Rules are *combinations* of evidence conditions.
- If any rule matches:
  - `verdict` is forced to `phishing`
  - `risk_score` is at least `block_threshold`

### 3.2 Risk fusion

Implementation: `scoring/fusion.py`.

- Multiply each factor `value` (0–1) by its `weight` to get `contribution`.
- Sum and clamp to 0–100.
- Output a `breakdown` (value/weight/contribution per factor).

Default weights live in `configs/profiles/balanced.yaml` (override `DEFAULT_WEIGHTS`).

### 3.3 Score-to-verdict mapping

- `score >= block_threshold` → `phishing`
- `score >= escalate_threshold` → `suspicious`
- else → `benign`

Thresholds are configured in `configs/profiles/balanced.yaml`.

## 4) Explanation output

`engine/explanation.py` produces `Explanation`:

- If a hard rule matched: `top_signals` includes `hard_rule:<code>` first.
- Otherwise: top signals are ranked `score_factor:<factor>` by contribution.
- `evidence` references structured evidence only (no raw email content).
