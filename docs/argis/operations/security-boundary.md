# Security Boundary

Argis keeps different trust boundaries for API and local CLI runtimes.

## API Mode (`POST /analyze`)

Assume untrusted input.

Rules:

- reject `eml_path`
- reject path-like attachment values
- sanitize sensitive evidence by default
- require explicit `debug_evidence=true` for full evidence

## Local CLI Mode

Assume operator-controlled environment.

Capabilities may include local file references and richer diagnostics.

## Guardrails

1. keep API validation strict and deterministic
2. keep side effects opt-in and bounded
3. avoid silent trust-boundary expansion in new fields
