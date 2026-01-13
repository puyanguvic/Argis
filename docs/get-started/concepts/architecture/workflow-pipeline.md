---
layout: default
title: End-to-End Workflow
redirect_from:
  - /architecture/workflow-pipeline.html
---

# End-to-end workflow

This page describes the full detection flow and how FAST/STANDARD/DEEP differ.

## 1) Ingestion

Two entry paths are supported:

- **JSON input**: CLI reads an `EmailInput` JSON (`apps/cli/main.py`).
- **Raw email**: `parse_raw_email()` converts to `EmailInput` (`tools_builtin/parser.py`), used by the demo.

## 2) Router: quick features + preliminary score

`engine/router.py` performs:

1. `header_auth_check(raw_headers)`: SPF/DKIM/DMARC extraction and alignment.
2. `quick_features(email)`: quick features from From/Reply-To, URL presence, subject keywords.

These are merged into a `preliminary_score` (0–100) and routed by thresholds:

- `prelim < t_fast` → `FAST`
- `prelim >= t_deep` → `DEEP`
- otherwise → `STANDARD`

Thresholds and tool sets are configured in `configs/profiles/balanced.yaml` (`engine/config.py`).

## 3) Orchestrator: execute tools by plan

`engine/orchestrator.py` executes `plan.tools` in order and writes to `EvidenceStore`:

- `header_auth_check` → `evidence.header_auth`
- `semantic_extract` → `evidence.semantic`
- `url_chain_resolve` → `evidence.url_chain`
- `domain_risk_assess` → `evidence.domain_risk`
- `attachment_static_scan` → `evidence.attachment_scan`

## 4) FAST contextual escalation

Some collaboration/OAuth emails lack classic malicious signals but still need more evidence. The system supports contextual escalation:

- Only when Router selects `FAST`, semantic intent matches collaboration intent, and brand/keyword rules match.
- Escalate profile from `FAST` to `STANDARD` and run additional tools (usually URL analysis).
- The escalation is written to `evidence.degradations` for audit (`engine/orchestrator.py`).

Note: escalation is a **routing signal** and does not directly add score.

## 5) Policy: hard rules + risk fusion

`engine/policy.py` runs:

1. `apply_hard_rules(evidence)`: force `phishing` if matched (`scoring/rules.py`).
2. `compute_risk_score(evidence, weights)`: weighted fusion with breakdown (`scoring/fusion.py`).
3. `map_score_to_verdict(score, thresholds)`: map to discrete verdicts.

## 6) Output: explanation + report / JSON

Outputs include:

- `Explanation`: top signals, recommended action, evidence references, score breakdown.
- Markdown report: `engine/report.py`.
- Machine JSON: `phish-agent detect --format json` (`apps/cli/main.py`).

## 7) Audit: record & replay

- `--record run.jsonl` records router, tool outputs, and final verdict (`engine/recorder.py`).
- `phish-agent replay --record run.jsonl` replays offline and recomputes verdict (`engine/player.py`).
