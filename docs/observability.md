# Observability

This page defines recommended metrics and logs for online analysis reliability.

## Core counters

- total analyze requests
- successful analyze responses
- fallback responses
- validation error responses (HTTP 4xx)

## Fallback metrics

Track:

- fallback count by `fallback_reason`
- fallback ratio (`fallback_count / total_requests`)
- trend by provider/model profile

Suggested alert:

- fallback ratio exceeds baseline threshold for sustained window

## Judge path metrics

- judge invocation count
- judge failure count
- judge failure ratio

## API validation metrics

- count by `detail.code`:
  - `invalid_text_type`
  - `unsupported_eml_path`
  - `invalid_attachment_schema`
  - `unsafe_attachment_path`

## Logging recommendations

Log per request:

- request id / trace id
- provider/model profile
- route/path (FAST/STANDARD/DEEP if available)
- verdict/risk_score
- fallback flag and `fallback_reason` (if present)
- duration and key stage timings (if available)

Avoid logging:

- raw sensitive email content in production logs unless explicit secure policy allows it
- full unsanitized evidence payloads by default
