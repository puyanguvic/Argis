---
title: Context Management
description: Guidance for preserving traceability, bounded evidence detail, and reproducible downstream triage context in Argis.
---

# Context Management

Context management in Argis should preserve determinism, traceability, and safety.

## Core Rules

- keep evidence references stable (`evidence_id` style where possible)
- preserve source/category metadata
- avoid opaque conclusions without indicators
- bound external fetch/analysis with explicit limits

The runtime now emits stable `evidence_id` references for selected judge-context evidence so downstream citations do not have to rely only on array-index paths.

## What “Context” Means Here

In Argis, context is not only model prompt text. It includes:

- normalized email metadata
- extracted URLs and attachment identifiers
- evidence-pack signals
- precheck summaries
- optional fetched or extracted artifact detail

Managing context well means keeping enough detail to explain the verdict, without turning the runtime into an unbounded artifact collector.

## API Context Rules

- default API responses expose `precheck` as the public summary and omit full internal `evidence`
- `debug_evidence=true` is for trusted debugging only

## Storage Guidance

For downstream systems, the most useful long-lived fields are usually:

- `verdict`
- `risk_score`
- `indicators`
- `fallback_reason`
- selected `precheck.component_scores`
- selected `runtime` metadata

You usually do not need to persist every nested evidence field by default.

## Practical Advice

Design downstream pipelines to store key indicators, runtime metadata, and fallback reasons for reproducible triage behavior.

## Related Docs

- [Configurations](/argis/configurations/)
- [Rules](/argis/configurations/rules)
- [Security Boundary](/argis/operations/security-boundary)
