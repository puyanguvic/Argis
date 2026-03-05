---
title: Overview
description: Product overview of Argis, including input modes, output structure, operating modes, and deterministic-first design goals.
---

# Overview

Argis is a phishing email detection system with deterministic-first analysis and evidence-backed outputs.

## What Argis Optimizes For

- Deterministic and auditable behavior by default.
- Clear boundary between policy, tools, and orchestration.
- Bounded side effects in online runtime.
- Traceable evidence references in final results.

## What Goes In

Argis accepts several input shapes, depending on the delivery interface:

- plain text, for fast local testing or simple service calls
- JSON-encoded message payloads, for structured fields such as subject, sender, URLs, attachments, and inline EML
- local `eml_path` input in CLI-oriented contexts

API mode is intentionally stricter than local CLI mode. In particular, API callers cannot submit `eml_path`, and attachment inputs must use logical object metadata rather than filesystem paths.

## What Comes Out

The final output is more than a label. A typical result includes:

- `verdict`: `benign`, `suspicious`, or `phishing`
- `risk_score`: bounded integer in `[0, 100]`
- `confidence`: bounded float in `[0.0, 1.0]`
- `indicators` and `recommended_actions`
- `provider_used`, including explicit fallback markers such as `openai:fallback`
- `precheck`, `runtime`, `skillpacks`, and `tools` metadata in API mode

When the API is used without `debug_evidence=true`, evidence is sanitized before response emission.

## Runtime Flow

1. Input parsing and normalization.
2. Evidence construction and precheck scoring.
3. Skill routing and optional deep analysis.
4. Optional judge pass and calibration.
5. Validation and final result emission.

## Operating Modes

### Deterministic-only execution

This is the baseline operating mode. Evidence building, pre-scoring, routing, and fallback output remain available even when remote model execution is disabled or unavailable.

### Judge-assisted execution

When a provider is configured and policy allows it, Argis can invoke a remote judge after deterministic evidence building. The judge does not replace the deterministic path; it is layered on top of it and its output is still merged and validated.

### Deep-analysis execution

Deep analysis is capability-based. URL fetching, OCR, and audio transcription are individually bounded and disabled by default. The `enable_deep_analysis` switch can turn them on as a one-shot bundle unless individual environment variables explicitly override them.

## Who This Page Is For

- engineers evaluating whether the system matches a deterministic-first security workflow
- operators deciding which runtime mode to enable
- API and platform owners who need to understand why the system can degrade gracefully instead of failing outright

## Continue Reading

- [Quickstart](./quickstart)
- [Concepts](./concepts)
- [Architecture Overview](/argis/architecture/design-overview)
