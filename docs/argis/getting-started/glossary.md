---
title: Glossary
description: Canonical terminology for Argis concepts such as EvidencePack, precheck, route, path, judge, fallback, profile, and deep analysis.
---

# Glossary

Use this page as the canonical vocabulary reference for Argis documentation. These terms are used with specific meanings across product, API, architecture, and operations pages.

## A

### API mode

The HTTP-facing runtime boundary exposed through `POST /analyze`. API mode is stricter than CLI mode: it validates request shape, rejects `eml_path`, rejects path-like attachment identifiers, and sanitizes evidence by default.

## C

### CLI mode

The local operator-facing runtime path. CLI mode is more permissive than API mode and can accept local file-oriented input such as `eml_path`.

### Context trigger score

A policy threshold that helps decide when the evidence stage should collect deeper web or attachment context. It is separate from the route thresholds used for `allow`, `review`, and `deep`.

## D

### Deep analysis

The broader capability family that may include URL fetching, OCR, QR decoding, and audio transcription. These capabilities are individually bounded and disabled by default.

### Deterministic-first

The design principle that Argis should build evidence and produce a workable result without requiring remote model execution. Optional judge usage is layered on top of the deterministic path rather than replacing it.

## E

### EvidencePack

The structured evidence object built by the runtime before any optional judge step. It contains normalized email metadata, header signals, URL signals, web signals, attachment signals, NLP cues, a pre-score, and provenance data.

## F

### Fallback

The degraded but valid result path used when parsing, evidence building, routing, or remote judge execution cannot complete normally. Fallback output is part of the runtime design, not an exceptional last-minute hack.

### Fallback reason

The explicit machine-readable explanation for why degraded execution was used. Examples include `remote_unavailable`, `parse_error:ValueError`, and `judge_error:RuntimeError`.

## J

### Judge

The optional remote evaluation stage that runs after deterministic evidence building. The judge can refine or merge with the deterministic view, but it does not eliminate fallback or validation guardrails.

### Judge allow mode

The policy setting that controls whether `allow`-route traffic may still be sent to the judge. Supported modes are `never`, `sampled`, and `always`.

## P

### Path

The delivery-facing runtime label emitted in final output:

- `FAST`
- `STANDARD`
- `DEEP`

It is derived from the internal route and represents the execution path at a higher level.

### Precheck

The structured summary returned alongside results that exposes key deterministic analysis details. It may include combined URLs, indicators, component scores, attachment checks, domain reports, fetch policy, and skill-trace metadata.

### Pre-score

The deterministic score and route computed from evidence before any optional judge involvement. It contains `risk_score`, `route`, and a list of reasons.

### Profile

The named runtime configuration bundle selected by `MY_AGENT_APP_PROFILE`, such as `ollama` or `openai`. A profile chooses a coherent provider/model baseline before environment overrides are applied.

### Provider

The model access backend used by the runtime, such as local/Ollama-oriented execution or OpenAI-compatible execution. Provider availability influences whether the judge can be called remotely.

## R

### Route

The internal execution classification chosen by deterministic scoring:

- `allow`
- `review`
- `deep`

It influences context collection, judge eligibility, and the final emitted path.

### Runtime metadata

The structured metadata returned in API responses that describes the active profile, provider, model, capability flags, policy thresholds, discovered skillpacks, and discovered tools.

## S

### Skill trace

The per-stage execution trace recorded in `precheck` that shows which fixed skills ran, their status, and elapsed time. It helps explain how the evidence stage executed for a given result.

### Skillpack

A local extension package stored under `skillpacks/` with instructions in `SKILL.md`. Skillpacks are discovered explicitly and surfaced in runtime metadata.

## T

### Tool

A deterministic execution capability registered in the built-in tool catalog. Tools perform bounded, inspectable work such as URL, header, text, or attachment analysis.

### Trust boundary

The security and input-assumption boundary that separates local operator workflows from remote caller workflows. In Argis, API and CLI modes intentionally do not share the same trust assumptions.

## Related Docs

- [Overview](./overview)
- [Concepts](./concepts)
- [Architecture](/argis/architecture/)
- [API](/api/)
