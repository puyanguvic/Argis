---
title: Runbook
description: First-response procedures for API validation errors, fallback spikes, evidence-detail issues, and documentation deployment problems.
---

# Runbook

This runbook documents first-response procedures for common runtime failures.

## Quick Triage

1. Confirm service health via `GET /health`.
2. Capture request shape and response details.
3. Record runtime metadata (`provider`, `model`, remote capability).
4. Separate caller validation failures from degraded but valid fallback results.

## First Questions To Answer

Before changing config or redeploying, determine:

- is the problem a bad request, a provider issue, or an internal runtime failure?
- is the system returning HTTP errors, or valid fallback responses?
- is the issue isolated to one profile/model or affecting all traffic?
- did the failure begin after a config, model, or release change?

## Incident: API Rejects Request Payload

Symptoms:

- HTTP 400 with `detail.code`

Actions:

1. `unsupported_eml_path`: switch to inline `eml` or `eml_raw`.
2. `invalid_attachment_schema`: convert attachments to object list.
3. `unsafe_attachment_path`: remove path-like attachment values.

Operator note:

- these are caller-data errors and should usually be fixed upstream, not retried unchanged.

## Incident: Unexpected Fallback Spike

Symptoms:

- increased responses where `provider_used` ends with `:fallback`

Actions:

1. Bucket by `fallback_reason`.
2. If `remote_unavailable`, check provider credentials/runtime.
3. If `judge_error`, inspect provider/model logs.
4. If `parse_error` or `evidence_build_error`, sample malformed inputs.

Additional checks:

5. confirm the active `runtime.profile` and `runtime.model`
6. confirm whether recent config changes altered judge eligibility or capability flags

## Incident: Docs Site Not Updated

Actions:

1. Check latest GitHub Pages workflow run.
2. Verify build and deploy jobs are green.
3. Hard-refresh site/CDN cache.

## Incident: Suspicious Results Lost Evidence Detail

Symptoms:

- operators expect full evidence fields but responses appear redacted

Actions:

1. verify whether the call path is API mode or local CLI mode
2. confirm whether `debug_evidence=true` was intentionally requested
3. do not disable sanitization globally just to debug one case

## Escalation

Escalate when fallback rate stays above baseline or repeated failure codes appear in production traffic.
