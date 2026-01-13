---
title: Evaluation Metrics
redirect_from:
  - /evaluation/metrics.html
---

# Evaluation metrics (precision / recall / risk)

We care about classification accuracy **and** whether risk scores and investigation cost are practical.

## 1) Classification metrics

- Precision / Recall / F1 (3-way or binary)
- Confusion matrix (focus on phishing false negatives)

## 2) Risk score quality

- Calibration: do scores map to actual risk likelihood?
- Stratification consistency: higher scores should reflect stronger evidence and lower FP rate.
- Top-signal stability: similar attacks should yield similar `top_signals`.

## 3) Routing and cost metrics

- Profile distribution: FAST/STANDARD/DEEP ratio
- Runtime: `runtime_ms` percentiles (p50/p95/p99)
- Evidence missing rate: key `EvidenceStore` fields empty by profile

## 4) Human workflow metrics

- `suspicious` escalation volume and handling time
- Confirmation rate after escalation (true malicious rate)
- False quarantine cost (benign quarantined)
