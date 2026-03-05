# Design Overview

Argis follows a deterministic-first architecture for phishing detection.

## Layer Model

1. `policy`: what to do and in what order.
2. `tools`: deterministic execution capabilities.
3. `orchestrator`: routing, retries, calibration, validation.
4. interfaces (`api`, `ui`, `cli`): delivery surfaces.

## Dependency Direction

- `policy` -> domain/config types
- `tools` -> domain/infra
- `orchestrator` -> policy/tools/domain/providers
- `api/ui/cli` -> orchestrator

## Design Priorities

- deterministic and auditable defaults
- bounded side effects
- evidence-backed risky outcomes
- explicit migration policy for interfaces

## Related Docs

- [Runtime Flow](./runtime-flow)
- [Rules](/argis/configurations/rules)
- [Security Boundary](/argis/operations/security-boundary)
