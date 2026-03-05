---
title: Runtime Flow
description: Step-by-step description of how Argis parses input, builds evidence, routes execution, invokes the judge, and emits validated output.
---

# Runtime Flow

Argis online runtime follows an explicit control flow.

1. Input parse and normalization.
2. Deterministic evidence construction and precheck scoring.
3. Skill routing (`allow/review/deep`).
4. Optional judge pass and score merge.
5. Output validation.
6. Final result emission with evidence/runtime metadata.

## Step By Step

### 1. Input parse and normalization

The runtime starts by converting the caller input into a normalized `EmailInput`. Structured JSON payloads may override subject, sender, URL, attachment, header, and inline EML fields. In API mode, caller data is validated before analysis begins.

### 2. Evidence construction

The evidence stage executes a fixed skill chain to collect:

- email surface and URL extraction
- header analysis
- URL and domain risk signals
- NLP cues
- attachment surface signals
- optional page-content and attachment-deep signals when context collection is justified

This stage also builds the `precheck` payload used in outputs. That payload includes combined URLs, hidden links, domain reports, attachment checks, component scores, fetch policy, and skill trace metadata.

### 3. Pre-score and route selection

The evidence stage produces a bounded `risk_score`, a route, and a list of reasons. The route is one of:

- `allow`
- `review`
- `deep`

The runtime maps those routes into the delivery path labels:

- `allow` -> `FAST`
- `review` -> `STANDARD`
- `deep` -> `DEEP`

### 4. Optional judge invocation

The skill router decides whether the judge should run. Judge execution requires:

- content to analyze
- a provider that can actually be called
- policy that permits judge usage for the selected route

`review` and `deep` routes are judge-eligible by default. `allow` routes can remain deterministic, or be sampled/always judged depending on `judge_allow_mode`.

### 5. Fallback handling

If parsing, evidence building, routing, or judge execution fails, the runtime emits deterministic fallback output. Known fallback reasons include:

- `empty_input`
- `remote_unavailable`
- `parse_error:<ExceptionType>`
- `evidence_build_error:<ExceptionType>`
- `skill_router_error:<ExceptionType>`
- `judge_error:<ExceptionType>`
- `no_final_result`

This is a core reliability path. The system prefers explainable degraded output over a blank failure.

### 6. Validation and final emission

Before final output is returned, online validation checks verdict shape, score range, and minimal evidence expectations for phishing verdicts. The API layer then applies response sanitization unless `debug_evidence=true` was explicitly requested.

## Reliability Guarantees

- deterministic fallback path is available
- fallback reasons are emitted for observability
- output shape is validated before final return
- runtime metadata records active profile, provider, model, enabled capabilities, and discovered skillpacks/tools

## What Operators Should Watch

- `fallback_reason`, because it separates remote availability issues from parsing or judge failures
- `provider_used`, because `:fallback` is the visible marker of degraded execution
- `precheck.component_scores`, because it explains which deterministic signals contributed most
- `skill_trace`, because it shows which fixed-stage skills actually ran and how long they took

Related docs:

- [Runbook](/argis/operations/runbook)
- [Observability](/argis/operations/observability)
- [Design Overview](/argis/architecture/design-overview)
