# Migration Guide

Use this guide when updating API clients across behavior changes in `POST /analyze`.

## Who Should Read This

- API consumers of `POST /analyze`
- teams parsing `precheck` or `evidence` response fields
- operators relying on fallback telemetry

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

### Evidence Is Sanitized by Default

Before:

- more detailed evidence internals could appear in API responses.

Now:

- default API responses redact sensitive evidence details.
- set `debug_evidence=true` only for trusted internal troubleshooting.

### Fallback Reason Is Explicit

Now:

- fallback responses include `fallback_reason` for observability.

## Upgrade Checklist

1. Remove `eml_path` from API payload generation.
2. Convert attachment input to object format.
3. Update parsers to tolerate sanitized default evidence fields.
4. Parse and monitor `fallback_reason`.
5. Use `debug_evidence=true` only in controlled internal contexts.

## Related Docs

- [API Contract](./contract)
- [API Reference](./reference)
- [Runbook](/argis/operations/runbook)
