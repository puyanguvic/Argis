---
title: Design Overview
description: Design rationale for the Argis policy, tools, orchestrator, and interface layers, with emphasis on evidence-first execution.
---

# Design Overview

Argis follows a deterministic-first architecture for phishing detection.

## Layer Model

1. `policy`: what to do and in what order.
2. `tools`: deterministic execution capabilities.
3. `orchestrator`: routing, retries, calibration, validation.
4. interfaces (`api`, `ui`, `cli`): delivery surfaces.

Each layer exists to keep the system explainable and evolvable:

- policy owns sequencing and priors, not side effects
- tools expose deterministic capabilities with bounded execution semantics
- orchestrator composes evidence building, route selection, judge usage, and fallback
- interfaces adapt external callers without leaking trust assumptions into core logic

## Dependency Direction

- `policy` -> domain/config types
- `tools` -> domain/infra
- `orchestrator` -> policy/tools/domain/providers
- `api/ui/cli` -> orchestrator

This dependency direction is operationally important. It prevents three common failure modes:

- policy logic drifting into tool implementations
- high-level interfaces reaching around orchestrator guardrails
- import structure turning into an implicit execution graph that is hard to reason about

## Design Priorities

- deterministic and auditable defaults
- bounded side effects
- evidence-backed risky outcomes
- explicit migration policy for interfaces

## Evidence-First Architecture

Argis is centered on the `EvidencePack` rather than on raw prompt orchestration. The evidence stage builds a structured pack containing:

- normalized email metadata
- header authentication and mismatch signals
- URL-level and domain-level risk signals
- optional web and attachment context
- NLP cue extraction
- a pre-score with route and reasons
- provenance such as stage timings, limits hit, and errors

That structure gives the rest of the runtime something concrete to operate on. The skill router reasons over deterministic evidence. The judge receives bounded context instead of the raw world. Validators can check the final result against known structural expectations.

## Policy-Centric Routing

`PipelinePolicy` centralizes the thresholds and judge behavior that shape online execution. Important values include:

- `pre_score_review_threshold`
- `pre_score_deep_threshold`
- `context_trigger_score`
- `suspicious_min_score`
- `suspicious_max_score`
- `judge_allow_mode`
- `judge_allow_sample_rate`

With default settings, the pre-score decides whether the message is in the `allow`, `review`, or `deep` band, and that route drives the runtime path (`FAST`, `STANDARD`, `DEEP`) as well as whether judge invocation is even considered.

## Why The Judge Is Optional

The judge is intentionally downstream of deterministic analysis. That means:

- the system can still produce a result when the remote provider is unavailable
- provider outages do not erase the heuristic evidence path
- runtime metadata can report whether the result came from the normal judge-assisted path or from deterministic fallback

This matters in security workflows, where the operator may prefer a conservative fallback result over a hard failure.

## Side-Effect Boundaries

URL fetch, OCR, QR decode, and audio transcription are separate capabilities with explicit configuration. They are bounded by timeouts, byte limits, redirect caps, and sandbox/backend choices. Deep analysis is therefore not “more AI”; it is a controlled extension of artifact collection under explicit limits.

## Related Docs

- [Runtime Flow](./runtime-flow)
- [Rules](/argis/configurations/rules)
- [Security Boundary](/argis/operations/security-boundary)
