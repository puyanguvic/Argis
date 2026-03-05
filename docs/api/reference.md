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

## Input Constraints

- `eml_path` is rejected in API mode.
- `attachments` must be object arrays with `name` or `filename`.
- Path-like attachment values are rejected.

## `POST /analyze` Response

Typical response fields:

- triage result: `verdict`, `risk_score`, `confidence`, `reason`, `indicators`
- runtime metadata: `precheck`, `runtime`, `skillpacks`, `tools`

Fallback case behavior:

- `provider_used` ends with `:fallback`
- `fallback_reason` is included for observability

Evidence behavior:

- default: sensitive evidence fields are sanitized
- `debug_evidence=true`: full evidence is included

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
