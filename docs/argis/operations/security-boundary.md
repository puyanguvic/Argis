---
title: Security Boundary
description: Trust-boundary model for Argis API and CLI modes, including validation, evidence sanitization, and side-effect guardrails.
---

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

That difference is intentional. CLI mode is a tool for trusted operators; API mode is a boundary exposed to potentially untrusted clients.

## Why The Boundary Matters

Without this separation, it would be too easy for remote callers to:

- smuggle filesystem assumptions into the API
- retrieve richer internal evidence than intended
- rely on behavior that is acceptable locally but unsafe over HTTP

Argis therefore keeps API validation and sanitization strict even when local developer workflows remain flexible.

## Guardrails

1. keep API validation strict and deterministic
2. keep side effects opt-in and bounded
3. avoid silent trust-boundary expansion in new fields

## Design Consequences

- new API fields should be evaluated as boundary changes, not just convenience additions
- local debug affordances should not be copied blindly into remote interfaces
- evidence exposure should default toward minimal necessary detail
