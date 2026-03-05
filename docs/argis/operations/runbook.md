# Runbook

This runbook documents first-response procedures for common runtime failures.

## Quick Triage

1. Confirm service health via `GET /health`.
2. Capture request shape and response details.
3. Record runtime metadata (`provider`, `model`, remote capability).

## Incident: API Rejects Request Payload

Symptoms:

- HTTP 400 with `detail.code`

Actions:

1. `unsupported_eml_path`: switch to inline `eml` or `eml_raw`.
2. `invalid_attachment_schema`: convert attachments to object list.
3. `unsafe_attachment_path`: remove path-like attachment values.

## Incident: Unexpected Fallback Spike

Symptoms:

- increased responses where `provider_used` ends with `:fallback`

Actions:

1. Bucket by `fallback_reason`.
2. If `remote_unavailable`, check provider credentials/runtime.
3. If `judge_error`, inspect provider/model logs.
4. If `parse_error` or `evidence_build_error`, sample malformed inputs.

## Incident: Docs Site Not Updated

Actions:

1. Check latest GitHub Pages workflow run.
2. Verify build and deploy jobs are green.
3. Hard-refresh site/CDN cache.

## Escalation

Escalate when fallback rate stays above baseline or repeated failure codes appear in production traffic.
