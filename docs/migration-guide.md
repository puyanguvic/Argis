# Migration Guide

> Migration note (2026-03-05): API-oriented migration context is now grouped under [/api/](/api/) and [/api/guides-concepts](/api/guides-concepts).

This guide covers migration for clients updating to `v0.1.1`.

## Who should read this

- API consumers of `POST /analyze`
- teams parsing `precheck` / `evidence` response fields
- operators relying on fallback telemetry

## Behavior changes

### 1. API `eml_path` is no longer accepted

Before:

- API callers could pass `eml_path` in JSON payload mode.

Now:

- API rejects `eml_path` with `unsupported_eml_path`.
- Use inline `eml` or `eml_raw` instead.

### 2. API attachments must be structured objects

Before:

- string attachment arrays could pass through.

Now:

- API requires object entries with `name` or `filename`.
- raw strings fail with `invalid_attachment_schema`.
- path-like values fail with `unsafe_attachment_path`.

### 3. Evidence is sanitized by default

Before:

- more detailed evidence internals could appear in API response.

Now:

- default API response redacts sensitive evidence details.
- set `debug_evidence=true` for internal troubleshooting detail.

### 4. Fallback reason is explicit

Now:

- fallback responses include `fallback_reason` for observability.

## Upgrade checklist

1. Remove `eml_path` from API payload generation.
2. Convert attachment input to object format.
3. Update parsers to tolerate sanitized default evidence fields.
4. Parse and monitor `fallback_reason`.
5. Use `debug_evidence=true` only in controlled internal contexts.
