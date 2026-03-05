# Concepts

Argis uses a layered control-stack architecture.

## Layers

1. `policy`: fixed policy priors and skill-chain guidance.
2. `tools`: deterministic capability execution.
3. `orchestrator`: runtime control stack, routing, and validation.
4. interfaces (`api`, `ui`, `cli`): delivery entry points.

## Key Design Rules

- Keep dependency direction one-way.
- Keep policy decisions out of side-effectful tool code.
- Keep high-risk outcomes evidence-backed.
- Keep migrations explicit and time-bounded.

## Where to Go Next

- [Architecture Overview](/argis/architecture/design-overview)
- [Runtime Flow](/argis/architecture/runtime-flow)
- [Configurations](/argis/configurations/)
