---
title: Risk Fusion and Scoring
redirect_from:
  - /pipeline/risk-scoring.html
---

# Risk fusion and scoring

This page describes how the risk score is computed and how configuration controls behavior.

## 1) Risk fusion

Implementation: `compute_risk_score(evidence, weights)` (`scoring/fusion.py`)

- Each factor yields a `value` (0/1 or 0–1)
- Contribution: `contribution = weight * value`
- Total score: sum contributions and clamp to 0–100
- Output: `(risk_score: int, breakdown: list[...])`

## 2) Default factors and sources

Factors from `scoring/fusion.py` (weights configurable in `configs/profiles/balanced.yaml`):

- Header:
  - `spf_fail` / `dkim_fail` / `dmarc_fail` from `evidence.header_auth`
- Router quick features:
  - `reply_to_mismatch` / `from_domain_mismatch` / `url_present` from `evidence.quick_features`
- URL:
  - `url_login_keywords` / `url_shortener` / `url_ip_host` / `url_suspicious_tld` from `evidence.url_chain`
- Domain:
  - `lookalike_domain` from `evidence.domain_risk`
- Semantic:
  - `semantic_credential_intent` when `semantic.intent == "credential_theft"`
  - `semantic_urgency` from `semantic.urgency_level / 3.0`
  - `collaboration_oauth_intent` when `semantic.intent` matches collaboration intent
- Attachments:
  - `attachment_macro` / `attachment_executable` from `evidence.attachment_scan`

## 3) Verdict mapping and thresholds

Implementation: `map_score_to_verdict()` (`scoring/fusion.py`)

- `score >= block_threshold` → `phishing`
- `score >= escalate_threshold` → `suspicious`
- else → `benign`

Thresholds: `configs/profiles/balanced.yaml` → `thresholds.*`.

## 4) Hard rules

Implementation: `apply_hard_rules()` (`scoring/rules.py`)

- Any rule match forces `phishing`.
- `risk_score` is at least `block_threshold`.

## 5) Tuning guidance

Tune in `configs/profiles/balanced.yaml`:

- Router: `t_fast` / `t_deep` and tool sets (affects cost/evidence depth)
- Weights: control factor contributions
- Thresholds: control `benign/suspicious/phishing` boundaries

Add or update regression samples in `tests/` to avoid unintended behavior changes.
