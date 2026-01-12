---
layout: default
title: Operations and Monitoring
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

- weight/threshold/rule updates must be traceable (see `governance/`)
- run benchmark scenarios for regression (see `evaluation/benchmarks.md`)
- keep rollback capability (versioned configs)

## 4) Audit and retention

- retain `run.jsonl` and events per privacy policy (`policies/privacy.md`)
- enforce access control and audit for sensitive records
