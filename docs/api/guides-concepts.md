# Guides and Concepts for the Argis API

Use this guide when integrating Argis into backend services, workers, and pipelines.

## API Design Principles

- Deterministic-first analysis path is always available.
- Side-effectful analysis is bounded and opt-in.
- High-risk outcomes should remain evidence-backed.
- Output shape is validated before final emission.

## Integration Patterns

### Synchronous service call

Best for low-volume direct user workflows.

- Call `POST /analyze` directly from your service.
- Return core triage fields and selected runtime metadata.

### Queue-based processing

Best for high-volume email ingestion.

- Push normalized payload into queue/topic.
- Worker calls Argis API and stores result + evidence references.
- Track fallback and validation rates per batch.

### Hybrid policy gate

Best when you need deterministic gating before human review.

- Use Argis output as machine triage.
- Route `suspicious` and high-risk samples to review queue.
- Store indicators and `fallback_reason` for analysts.

## Operational Recommendations

1. Enforce request schema in callers.
2. Treat API `400` errors as caller-data issues.
3. Monitor `provider_used` and `fallback_reason`.
4. Use `debug_evidence=true` only in trusted contexts.

## Related Docs

- [API Reference](./reference)
- [API Contract](./contract)
- [Migration Guide](./migration-guide)
- [Runbook](/argis/operations/runbook)
- [Security Boundary](/argis/operations/security-boundary)
