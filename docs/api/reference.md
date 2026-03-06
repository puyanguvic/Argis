---
title: API Reference
description: Reference documentation for Argis API requests, responses, runtime metadata, fallback semantics, and validation errors.
---

# API Reference

This page summarizes the stable API contract for Argis.

Canonical low-level contract details remain in [API Contract](./contract).

## Endpoints

- `GET /health`
- `POST /analyze`

## `POST /analyze` Request

Content type:

- `application/json`

Top-level fields:

- `text` (required, string)
- `model` (optional, string)
- `debug_evidence` (optional, boolean-like)

### `text` Input Modes

1. Plain text mode:

```json
{
  "text": "Please verify your account now."
}
```

2. JSON mode (stringified payload):

```json
{
  "text": "{\"subject\":\"Notice\",\"urls\":[\"https://example.com\"],\"attachments\":[{\"name\":\"invoice.pdf\"}]}"
}
```

Allowed structured keys inside JSON mode include:

- headers/metadata: `subject`, `sender`, `reply_to`, `return_path`, `message_id`, `date`
- recipients: `to`, `cc`
- body: `text`, `body_text`, `body_html`
- deep input: `headers`, `urls`, `attachments`, `eml`, `eml_raw`

### Notes on Request Semantics

- `text` must always be a string at the transport level.
- `model` acts as a per-request override when a non-empty string is provided.
- `debug_evidence` is parsed as a boolean-like field; truthy values include `1`, `true`, `yes`, and `on`.

## Input Constraints

- `eml_path` is rejected in API mode.
- `attachments` must be object arrays with `name` or `filename`.
- Path-like attachment values are rejected.
- malformed stringified JSON inside `text` falls back to plain-text treatment rather than transport-level validation failure

## `POST /analyze` Response

Typical response fields:

- triage result: `verdict`, `risk_score`, `confidence`, `reason`, `indicators`
- runtime metadata: `precheck`, `runtime`, `skillpacks`, `tools`
- delivery/runtime state: `path`, `provider_used`, `fallback_reason`
- message context echoes: `input`, `urls`, `attachments`

Fallback case behavior:

- `provider_used` ends with `:fallback`
- `fallback_reason` is included for observability

Evidence behavior:

- default: `precheck` remains available as the public summary, but full internal `evidence` is omitted
- `debug_evidence=true`: full evidence is included

### Representative Response Shape

```json
{
  "verdict": "phishing",
  "reason": "Evidence pack indicates coordinated phishing signals.",
  "path": "STANDARD",
  "risk_score": 42,
  "confidence": 0.76,
  "indicators": ["credential_request", "hidden_html_links"],
  "recommended_actions": [
    "Do not click unknown links",
    "Verify sender through trusted channel",
    "Escalate to analyst review before user interaction"
  ],
  "provider_used": "local:fallback",
  "fallback_reason": "remote_unavailable",
  "precheck": {
    "combined_urls": ["https://example.com/reset"],
    "indicators": ["credential_request", "hidden_html_links"],
    "component_scores": {
      "text": 54,
      "url": 32,
      "domain": 18,
      "attachment": 0,
      "ocr": 0
    }
  },
  "runtime": {
    "profile": "ollama",
    "provider": "local",
    "model": "ollama/qwen2.5:7b",
    "enable_url_fetch": false,
    "enable_ocr": false,
    "enable_audio_transcription": false,
    "can_call_remote": false
  }
}
```

The exact response contains additional fields, but the shape above captures the parts most callers usually depend on.

## Runtime Metadata Highlights

The `runtime` payload contains more than provider details. It also reports:

- active profile and model choices
- enabled deep-analysis capabilities
- scoring and judge-policy thresholds
- discovered skillpacks
- discovered built-in tools

For observability and dashboards, prefer stable high-signal fields such as `profile`, `provider`, `model`, `can_call_remote`, `enable_url_fetch`, and `judge_allow_mode`.

## Error Format

Validation errors return HTTP `400` with:

```json
{
  "detail": {
    "code": "error_code",
    "message": "human readable message"
  }
}
```

Known `code` values:

- `invalid_text_type`
- `unsupported_eml_path`
- `invalid_attachment_schema`
- `unsafe_attachment_path`

These errors are caller-correctable. They should not be retried without modifying the request payload.
