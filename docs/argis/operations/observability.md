---
title: Observability
description: Metrics, logs, and high-signal dashboards for monitoring Argis reliability, fallback behavior, and caller quality.
---

# Observability

Recommended metrics and logs for online reliability.

## Core Metrics

- total analyze requests
- successful responses
- fallback responses
- validation failures (HTTP 4xx)

These four counters answer the first operational question: is the system healthy, degraded, or being called incorrectly?

## Fallback Metrics

Track:

- fallback count by `fallback_reason`
- fallback ratio (`fallback_count / total_requests`)
- trend by provider/model profile

Do not collapse all fallback modes into a single alert. `remote_unavailable` and `judge_error` have different operational meanings from `parse_error` or `evidence_build_error`.

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
- context-admission status (`admitted`, `skipped_by_policy`, `skipped_by_score`, `skipped_by_signal`)

Avoid logging raw sensitive email content unless explicitly allowed by security policy.

## High-Signal Fields

If you only have room to build a small dashboard, prioritize:

- total requests
- HTTP 4xx rate
- fallback ratio
- fallback count by `fallback_reason`
- `provider_used` distribution
- `path` distribution (`FAST`, `STANDARD`, `DEEP`)
- context-admission breakdown for web and attachment-deep collection

## Useful Derived Views

### Reliability view

- success rate
- fallback ratio
- judge failure ratio

### Caller quality view

- validation error rate
- top `detail.code` values

### Behavior drift view

- score distribution over time
- route/path distribution over time
- fallback rate by model/profile
