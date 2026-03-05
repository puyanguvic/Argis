---
title: Migration Guide
description: Upgrade guidance for Argis API consumers when request validation, evidence defaults, or fallback telemetry change.
---

# Migration Guide

Use this guide when updating API clients across behavior changes in `POST /analyze`.

## Who Should Read This

- API consumers of `POST /analyze`
- teams parsing `precheck` or `evidence` response fields
- operators relying on fallback telemetry

## Migration Strategy

When upgrading API consumers, separate the work into three categories:

- request-shape changes your caller must send correctly
- response-shape changes your parser must tolerate
- observability changes your dashboards and alerts should start using

## v0.1.1 Behavior Changes

### `eml_path` Is No Longer Accepted in API Mode

Before:

- API callers could pass `eml_path` in JSON payload mode.

Now:

- API rejects `eml_path` with `unsupported_eml_path`.
- Use inline `eml` or `eml_raw` instead.

### Attachments Must Be Structured Objects

Before:

- string attachment arrays could pass through.

Now:

- API requires object entries with `name` or `filename`.
- raw strings fail with `invalid_attachment_schema`.
- path-like values fail with `unsafe_attachment_path`.

Recommended migration:

- normalize attachment input in the caller before sending the request
- treat the API as a logical message interface, not a file-access interface

### Evidence Is Sanitized by Default

Before:

- more detailed evidence internals could appear in API responses.

Now:

- default API responses redact sensitive evidence details.
- set `debug_evidence=true` only for trusted internal troubleshooting.

Recommended migration:

- stop assuming every nested evidence detail is always present
- update analyst tooling to request debug evidence only in controlled contexts

### Fallback Reason Is Explicit

Now:

- fallback responses include `fallback_reason` for observability.

Recommended migration:

- add `fallback_reason` to logs, dashboards, and triage reports
- separate `remote_unavailable` issues from parse or judge failures

## Upgrade Checklist

1. Remove `eml_path` from API payload generation.
2. Convert attachment input to object format.
3. Update parsers to tolerate sanitized default evidence fields.
4. Parse and monitor `fallback_reason`.
5. Use `debug_evidence=true` only in controlled internal contexts.

## Recommended Validation After Upgrade

- run at least one plain-text request and one structured JSON request
- verify that HTTP `400` caller errors still surface correctly
- verify that your parser handles fallback responses with `provider_used=*:*fallback`
- verify that dashboards or logs now capture `fallback_reason`

## Related Docs

- [API Contract](./contract)
- [API Reference](./reference)
- [Runbook](/argis/operations/runbook)
