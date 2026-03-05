---
title: Guides and Concepts
description: Integration patterns and operating guidance for services, workers, and pipelines that call the Argis HTTP API.
---

# Guides and Concepts for the Argis API

Use this guide when integrating Argis into backend services, workers, and pipelines.

## API Design Principles

- Deterministic-first analysis path is always available.
- Side-effectful analysis is bounded and opt-in.
- High-risk outcomes should remain evidence-backed.
- Output shape is validated before final emission.

## The Most Important Integration Fact

`POST /analyze` always expects a top-level JSON object whose `text` field is a string. That string can be:

- plain email-like text
- a stringified JSON payload containing structured message fields

This is deliberate. The transport contract remains simple, while the normalized email payload can still contain richer fields such as `subject`, `urls`, `attachments`, `headers`, `eml`, or `eml_raw`.

## How To Think About Response Handling

Treat the response as three layers:

### 1. Triage outcome

These are the fields most business logic will use:

- `verdict`
- `risk_score`
- `confidence`
- `reason`
- `indicators`
- `recommended_actions`

### 2. Runtime explanation

These fields explain how the result was produced:

- `provider_used`
- `fallback_reason`
- `path`
- `runtime`

### 3. Evidence and precheck detail

These fields support analyst review, debugging, and observability:

- `precheck`
- `evidence`
- `skillpacks`
- `tools`

## Integration Patterns

### Synchronous service call

Best for low-volume direct user workflows.

- Call `POST /analyze` directly from your service.
- Return core triage fields to the caller.
- Log `provider_used`, `path`, `risk_score`, and `fallback_reason` internally.
- Avoid returning full evidence to end users unless you control the trust boundary.

### Queue-based processing

Best for high-volume email ingestion.

- Push normalized payload into queue/topic.
- Worker calls Argis API and stores result + evidence references.
- Track fallback and validation rates per batch.
- Persist `precheck.indicators`, `precheck.component_scores`, and selected runtime fields for later auditing.

### Hybrid policy gate

Best when you need deterministic gating before human review.

- Use Argis output as machine triage.
- Route `suspicious` and high-risk samples to review queue.
- Store indicators and `fallback_reason` for analysts.

## Input Strategy Recommendations

### Prefer structured JSON mode when you already have parsed email data

If your upstream pipeline already knows subject, sender, URLs, or attachments, send them explicitly. This gives the parser less guesswork and makes downstream evidence more reproducible.

### Keep attachment values logical

The API intentionally rejects filesystem-style attachment values. Use names like `invoice.pdf`, not `/tmp/invoice.pdf` or `file:///tmp/invoice.pdf`.

### Treat inline EML as content, not a host path

If you need raw email fidelity in API mode, use `eml` or `eml_raw`. Do not send local file paths.

## Response Strategy Recommendations

### Distinguish HTTP errors from fallback output

- HTTP `400` means caller input failed validation.
- HTTP `200` with `provider_used` ending in `:fallback` means Argis returned a valid degraded result.

Those two cases should drive different operational actions.

### Use `debug_evidence=true` sparingly

API responses are sanitized by default because they may cross trust boundaries. Only enable full evidence in trusted debugging or internal analysis workflows.

### Watch runtime capability state

The `runtime` object tells you which profile, provider, model, and deep-analysis capabilities were active. This is useful when comparing results across environments.

## Operational Recommendations

1. Enforce request schema in callers.
2. Treat API `400` errors as caller-data issues.
3. Monitor `provider_used` and `fallback_reason`.
4. Use `debug_evidence=true` only in trusted contexts.

## Related Docs

- [API Reference](./reference)
- [API Contract](./contract)
- [Migration Guide](./migration-guide)
- [Runbook](/argis/operations/runbook)
- [Security Boundary](/argis/operations/security-boundary)
