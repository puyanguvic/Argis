# Changelog

All notable changes to this project are documented in this file.

## 2026-03-05

### Added
- Route-aware judge context and stable evidence references:
  - introduced bounded `judge_context` payloads for `FAST`, `STANDARD`, and `DEEP`
  - added stable `evidence_id` references for selected judge-context evidence
  - backfilled `top_evidence.evidence_id` from cited context paths when available
  - surfaced `evidence_refs` and route-aware `judge_context` in internal evidence payloads
  - Related issues: #13, #15

- API input hardening for `/analyze`:
  - rejected `eml_path` in API JSON requests
  - enforced structured attachment schema (`name`/`filename`)
  - rejected path-like attachment values in API mode
  - added stable 400 validation error codes
  - Related issue: #7
  - Commit: `52aa093`

- API evidence exposure controls:
  - default response sanitization for sensitive evidence fields
  - `debug_evidence=true` support for full evidence details
  - Related issue: #8
  - Commit: `a52f36f`

- Deterministic fallback reliability improvements:
  - guaranteed fallback on parse/evidence/router/judge failures
  - introduced `fallback_reason` in fallback responses
  - added failure-injection regression tests
  - Related issue: #9
  - Commit: `44dc217`

### Changed
- Precheck tuning now has effective scoring impact:
  - wired URL/domain/text-related tuning knobs into pre-score logic
  - expanded tuning tests to validate score movement under env overrides
  - Related issue: #10
  - Commit: `8421ba3`

- Policy and threshold consistency:
  - replaced hardcoded phishing threshold assumptions with policy-driven semantics
  - aligned verdict normalization/merge behavior with `suspicious_max_score + 1`
  - runtime metadata now reports actual SDK availability/capability
  - Related issue: #11
  - Commit: `d339beb`

- Documentation alignment:
  - updated `README.md`, `docs/argis/`, and `docs/api/`
  - documented API input boundaries, evidence sanitization, and fallback taxonomy
  - Related issue: #12
  - Commit: `8e3459f`

- Context-engineering runtime alignment:
  - split deep-context admission into independent web and attachment gates
  - added structured `context_admissions` metadata with admitted/skipped/capped states
  - tightened API default output to omit full internal `evidence` unless `debug_evidence=true`
  - updated architecture, blog, API, observability, and runbook docs to match shipped behavior
  - Related issues: #14, #16, #17

### Validation
- `ruff check src tests docs scripts`
- `pytest -k 'not hf_phishing_email_balanced_sample'`
