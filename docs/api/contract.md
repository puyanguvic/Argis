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

## Attachment Schema

`attachments` must be a list of objects such as:

- `{ "name": "invoice.pdf" }`
- `{ "filename": "report.docx" }`

Rejected patterns:

- raw string arrays such as `["invoice.pdf"]`
- path-like values such as `../x`, `/tmp/x`, `C:\\x`, or `file://...`

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

## Evidence Behavior

Default behavior:

- sensitive evidence fields are sanitized in API responses

Debug behavior with `debug_evidence=true`:

- full evidence details are returned for internal diagnostics

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
