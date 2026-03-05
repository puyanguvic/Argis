---
title: Integrations
description: Patterns and anti-patterns for embedding Argis into ingestion pipelines, analyst tooling, and batch evaluation flows.
---

# Integrations

Argis supports multiple integration paths.

## Integration Goal

Treat Argis as a deterministic-first triage component, not as an isolated black-box model call. Good integrations preserve:

- normalized upstream message context
- runtime metadata for auditability
- fallback signals for observability
- downstream handling that respects trust boundaries

## HTTP API

- Use `POST /analyze` from web services, workers, and pipelines.
- Validate input schema before sending requests.

## Provider Profiles

- OpenAI profile via `MY_AGENT_APP_PROFILE=openai` and `OPENAI_API_KEY`.
- Local Ollama profile via `MY_AGENT_APP_PROFILE=ollama`.

## Skillpacks

- Local discovery from `skillpacks/`.
- Install/update via `scripts/skillsbench_skillpacks.py`.

## Observability Integration

- Capture `fallback_reason` and runtime metadata in logs/metrics.
- Track validation and fallback rates as reliability signals.

## Recommended Integration Patterns

### Ingestion pipeline

- normalize email content upstream
- call Argis once per message
- persist verdict, score, indicators, and selected `precheck` fields
- route suspicious output into analyst review systems

### Analyst tooling

- call the API with `debug_evidence=true` only in trusted contexts
- preserve `provider_used`, `path`, and `fallback_reason` for case context
- expose evidence-backed indicators instead of only the final label

### Batch evaluation or replay

- keep the input payload stable and explicit
- store runtime profile and model metadata alongside results
- compare fallback rate and score drift across runs

## Anti-Patterns To Avoid

- treating HTTP `200` fallback output as indistinguishable from judge-assisted output
- sending filesystem paths through the API
- tightly coupling downstream parsers to every nested field in `runtime.config`
- logging raw sensitive evidence by default
