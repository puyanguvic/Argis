---
layout: default
title: Model Update Policy
---

# Model update policy

Models are allowed, but the principle is: **models are evidence sources, not final decision makers**.

## 1) Separate evidence from decisions

Recommended pattern:

- model output writes into a new `EvidenceStore` field (e.g., `llm_semantic`)
- scoring/rules reference that field with explainable contributions
- if the model is unavailable, the system should degrade and record it

## 2) Versioning and evaluation

For model updates:

- record `model_version` in events
- compare new vs old on fixed benchmarks (`evaluation/`)
- canary rollouts with monitoring for FP/FN and runtime

## 3) Rollback and audit

- keep fast rollback (disable model evidence via config)
- use JSONL record/replay to compare before/after and localize changes

`models/lightweight_classifier/` is a placeholder that can follow this policy.
