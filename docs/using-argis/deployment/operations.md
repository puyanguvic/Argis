---
layout: default
title: Operations and Monitoring
redirect_from:
  - /deployment/operations.html
---

# Operations and monitoring

Suggested metrics and operational practices.

## 1) Runtime and stability

- `runtime_ms`: p50/p95/p99
- profile distribution: FAST/STANDARD/DEEP
- tool error rate (when extended): timeout/exception/egress denied
- evidence missing rate: key fields empty

## 2) Quality monitoring

- `phishing` hit rate and confirmed true-positive rate
- `suspicious` escalation volume and SLA
- false positive/negative samples and postmortems

## 3) Change governance

- weight/threshold/rule updates must be traceable (see `get-started/concepts/governance/`)
- run benchmark scenarios for regression (see `get-started/concepts/evaluation/benchmarks.md`)
- keep rollback capability (versioned configs)

## 4) Audit and retention

- retain `run.jsonl` and events per privacy policy (`get-started/concepts/policies/privacy.md`)
- enforce access control and audit for sensitive records
