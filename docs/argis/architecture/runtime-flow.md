# Runtime Flow

Argis online runtime follows an explicit control flow.

1. Input parse and normalization.
2. Deterministic evidence construction and precheck scoring.
3. Skill routing (`allow/review/deep`).
4. Optional judge pass and score merge.
5. Output validation.
6. Final result emission with evidence/runtime metadata.

## Reliability Guarantees

- deterministic fallback path is available
- fallback reasons are emitted for observability
- output shape is validated before final return

Related docs:

- [Runbook](/argis/operations/runbook)
- [Observability](/argis/operations/observability)
- [Design Overview](/argis/architecture/design-overview)
