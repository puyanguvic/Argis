---
title: API Contract
description: Stable low-level wire contract for POST /analyze, including request rules, response guarantees, and error codes.
---

# API Contract

This page defines the stable low-level contract for `POST /analyze`.

## Endpoint

- `POST /analyze`

## Content Type

- `application/json`

## Top-Level Fields

- `text` (required, string)
- `model` (optional, string)
- `debug_evidence` (optional, boolean-like)

## Transport-Level Rule

The request body must be a JSON object, and `text` must be present as a string. Even when you are sending structured message data, that structure is carried inside the string value of `text`.

## `text` Payload Modes

`text` can be plain text or a JSON-encoded string.

### Plain Text Mode

```json
{
  "text": "Please verify your account now."
}
```

### JSON Mode

```json
{
  "text": "{\"subject\":\"Notice\",\"urls\":[\"https://example.com\"],\"attachments\":[{\"name\":\"invoice.pdf\"}]}"
}
```

Allowed JSON keys inside `text`:

- `subject`, `sender`, `reply_to`, `return_path`, `message_id`, `date`
- `to`, `cc`
- `text`, `body_text`, `body_html`
- `headers`
- `urls`
- `attachments`
- `eml`, `eml_raw`

Disallowed in API mode:

- `eml_path`

### Why `eml_path` Is Disallowed

The API is treated as an untrusted boundary. Local filesystem paths would leak host assumptions into a remote caller contract, so API mode accepts inline content only.

## Attachment Schema

`attachments` must be a list of objects such as:

- `{ "name": "invoice.pdf" }`
- `{ "filename": "report.docx" }`

Rejected patterns:

- raw string arrays such as `["invoice.pdf"]`
- path-like values such as `../x`, `/tmp/x`, `C:\\x`, or `file://...`

The API treats attachment entries as logical identifiers for analysis context, not as direct filesystem access instructions.

## Response Shape

Base response includes:

- triage fields such as `verdict`, `risk_score`, `reason`, `confidence`, `indicators`
- `precheck`
- `runtime`
- `skillpacks`
- `tools`

When fallback is used:

- `provider_used` ends with `:fallback`
- `fallback_reason` is present

The `fallback_reason` field is part of the observable runtime contract for degraded execution. It is important for operators even when the HTTP status is still `200`.

## Evidence Behavior

Default behavior:

- sensitive evidence fields are sanitized in API responses

Debug behavior with `debug_evidence=true`:

- full evidence details are returned for internal diagnostics

This distinction is intentional. API consumers often cross a wider trust boundary than local CLI users.

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

Known error codes:

- `invalid_text_type`
- `unsupported_eml_path`
- `invalid_attachment_schema`
- `unsafe_attachment_path`

## Stability Guidance

Callers should treat these fields as the stable public contract:

- request: `text`, `model`, `debug_evidence`
- response: core triage fields, `provider_used`, `fallback_reason`, `precheck`, `runtime`, `skillpacks`, `tools`
- errors: `detail.code`, `detail.message`

Callers should avoid tightly coupling to every nested field inside `runtime.config` or other implementation-detail-heavy substructures.
