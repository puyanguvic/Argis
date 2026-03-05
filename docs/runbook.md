# Operations Runbook

This runbook documents first-response procedures for common runtime failures.

## Quick triage

1. Confirm service health:
   - `GET /health`
2. Capture failing request shape and response:
   - HTTP status
   - `detail.code` (for 4xx validation errors)
   - `fallback_reason` (for fallback outputs)
3. Check deployment/runtime metadata:
   - `runtime.provider`
   - `runtime.model`
   - `runtime.can_call_remote`

## Common incidents

### Incident: API rejects request payload

Symptoms:

- HTTP 400 with `detail.code`

Actions:

1. If `unsupported_eml_path`, move to inline `eml` / `eml_raw`.
2. If `invalid_attachment_schema`, convert attachments to object list.
3. If `unsafe_attachment_path`, remove filesystem/path-style attachment values.

### Incident: Unexpected fallback spike

Symptoms:

- increased `provider_used` ending in `:fallback`

Actions:

1. Bucket by `fallback_reason`.
2. If `remote_unavailable`, verify API key/provider runtime.
3. If `judge_error`, inspect upstream model/provider logs.
4. If `parse_error` or `evidence_build_error`, sample payloads for malformed input patterns.

### Incident: Pages site not updated

Actions:

1. Open latest workflow run: `Deploy VitePress to GitHub Pages`.
2. Verify `build` and `deploy` jobs are green.
3. Hard refresh site to bypass CDN cache.

## Escalation

Escalate to engineering when:

- fallback rate sustains above normal baseline.
- same `fallback_reason` repeats for production traffic.
- API contract rejects previously valid production payloads.
