# Observability

Recommended metrics and logs for online reliability.

## Core Metrics

- total analyze requests
- successful responses
- fallback responses
- validation failures (HTTP 4xx)

## Fallback Metrics

Track:

- fallback count by `fallback_reason`
- fallback ratio (`fallback_count / total_requests`)
- trend by provider/model profile

## Judge Path Metrics

- judge invocation count
- judge failure count
- judge failure ratio

## Validation Metrics

Track by `detail.code`:

- `invalid_text_type`
- `unsupported_eml_path`
- `invalid_attachment_schema`
- `unsafe_attachment_path`

## Logging Recommendations

Log per request:

- request/trace id
- provider and model profile
- route/depth (if present)
- verdict and risk score
- fallback flags and reasons
- duration/stage timing

Avoid logging raw sensitive email content unless explicitly allowed by security policy.
