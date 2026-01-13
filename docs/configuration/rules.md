---
layout: default
title: Rules and Weights
redirect_from:
  - /governance/rule-lifecycle.html
---

# Rules and weights

Rules and weights directly affect blocking and alerts, so change control is required.

In this project:

- **Hard rules** live in `scoring/rules.py` and force `phishing` on match.
- **Weights** live in `scoring/fusion.py` with overrides in `configs/profiles/*.yaml`.
- **Thresholds** live in `engine/policy.py` with overrides in `configs/profiles/*.yaml` (`thresholds.*`).

## 1) Change types

- Routing thresholds: investigation cost and evidence depth (`router.*` in `configs/profiles/balanced.yaml`)
- Scoring weights: score and `top_signals` (`scoring/fusion.py` + config)
- Hard rules: forced blocking (`scoring/rules.py`)

## 2) Recommended change process

1. Define goals and risk (what FP/FN are you targeting?)
2. Submit change:
   - config update or code change
   - update docs (skill/factor references)
3. Regression validation:
   - benchmark scenarios + unit tests (`tests/` + `get-started/concepts/evaluation/benchmarks.md`)
4. Release strategy:
   - canary rollout (small traffic or low-risk tenants)
   - monitor key metrics (false blocks, misses, SLA)
5. Postmortem and documentation:
   - record reason, samples, and outcomes

## 3) Rule coding and traceability

- Hard rules should have stable match codes (`scoring/rules.py`).
- `evidence_id` in reports should map to rules/factors (see `using-argis/reporting/evidence-table.md`).
