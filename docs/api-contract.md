# API Contract

This page defines the stable contract for `POST /analyze`.

## Request

Endpoint:

- `POST /analyze`

Content type:

- `application/json`

Top-level fields:

- `text` (required, string)
- `model` (optional, string)
- `debug_evidence` (optional, boolean-like)

## `text` payload modes

`text` can be plain text or a JSON-encoded string.

### Plain text mode

Example:

```json
{
  "text": "Please verify your account now."
}
```

### JSON mode

Example:

```json
{
  "text": "{\"subject\":\"Notice\",\"urls\":[\"https://example.com\"],\"attachments\":[{\"name\":\"invoice.pdf\"}]}"
}
```

Allowed JSON keys (inside `text`):

- `subject`, `sender`, `reply_to`, `return_path`, `message_id`, `date`
- `to`, `cc`
- `text`, `body_text`, `body_html`
- `headers`
- `urls`
- `attachments` (API mode: object list only)
- `eml`, `eml_raw`

Disallowed in API mode:

- `eml_path`

## Attachment schema (API mode)

`attachments` must be a list of objects:

- `{ "name": "invoice.pdf" }`
- `{ "filename": "report.docx" }`

Rejected patterns:

- raw string arrays (e.g., `["invoice.pdf"]`)
- path-like values (e.g., `../x`, `/tmp/x`, `C:\\x`, `file://...`)

## Response

Base response includes:

- triage fields (`verdict`, `risk_score`, `reason`, `confidence`, `indicators`, ...)
- `precheck`
- `runtime`
- `skillpacks`
- `tools`

When fallback is used:

- `provider_used` ends with `:fallback`
- `fallback_reason` is present

## Evidence behavior

Default (`debug_evidence` unset/false):

- sensitive evidence fields are sanitized in API responses

Debug mode (`debug_evidence=true`):

- full evidence details are returned for internal diagnostics

## Error format

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
