# Security Boundary

Argis uses different trust boundaries for API and local runtime contexts.

## Boundary model

### API mode (`POST /analyze`)

Assume untrusted input.

Rules:

- reject local file path ingestion (`eml_path`)
- reject path-like attachment names
- sanitize sensitive evidence fields by default
- require explicit `debug_evidence=true` for full evidence detail

### Local CLI mode

Assume operator-controlled environment.

Capabilities may include:

- local filesystem references (for example local EML path usage)
- richer local diagnostics

## Why this separation exists

- API is internet-facing and must not expose filesystem or host internals.
- CLI is operator tooling where local paths and direct diagnostics are expected.

## Guardrails

1. Keep API validation strict and deterministic.
2. Keep side-effectful capabilities opt-in and bounded.
3. Do not silently widen API trust assumptions when adding new input fields.
