# Argis Documentation

This site is the web documentation for **Argis**, a phishing email detection agent with deterministic-first analysis and policy-controlled runtime behavior.

## Start Here

- [Manual](./manual): runbook, configuration, API usage, and testing commands.
- [Design](./design): architecture model, contracts, runtime flow, and guardrails.
- [API Contract](./api-contract): request/response schema, errors, and compatibility expectations.
- [Migration Guide](./migration-guide): behavior changes and caller migration checklist.
- [Runbook](./runbook): production troubleshooting and incident handling steps.
- [Observability](./observability): metrics, logs, and dashboard recommendations.
- [Security Boundary](./security-boundary): trust boundaries for API vs local runtime.
- [Release Gates](./release-gates): required checks and release readiness criteria.
- [Changelog](./changelog): release-facing summary of recent changes.
- [Release Notes](./releases): links to GitHub release pages.

## Current Focus (v0.1.1)

Recent updates shipped in `v0.1.1`:

- Hardened `/analyze` API input boundaries.
- Default evidence sanitization for API responses with explicit `debug_evidence=true` opt-in.
- Fallback reliability improvements with `fallback_reason`.
- Precheck tuning knobs wired to effective scoring behavior.
- Policy-driven threshold semantics and runtime capability metadata alignment.

For full details, see:

- [v0.1.1 release page](https://github.com/puyanguvic/Argis/releases/tag/v0.1.1)
- [CHANGELOG.md](https://github.com/puyanguvic/Argis/blob/main/CHANGELOG.md)
