---
title: Concepts
description: Conceptual introduction to Argis layers, evidence-first execution, routing, capability flags, and fallback behavior.
---

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

## Important Runtime Ideas

### Evidence first

The system builds an `EvidencePack` before any optional judge step. That pack contains normalized metadata, header signals, URL signals, attachment signals, NLP cues, a pre-score, and provenance such as timing and limits hit.

### Route before judge

The deterministic pre-score does more than rank risk. It also chooses the route:

- `allow`
- `review`
- `deep`

Those routes map to the runtime path and influence whether deeper context collection or judge invocation is warranted.

### Capability flags are explicit

Side-effectful capabilities such as URL fetch, OCR, and audio transcription are not implicitly on. Operators must enable them through configuration, and the API keeps separate trust-boundary rules from local execution.

### Fallback is part of the design

Argis is intentionally built to degrade into deterministic fallback output if remote provider access, judge evaluation, parsing, or evidence construction fails. This is a runtime property, not an exceptional edge case.

## Where to Go Next

- [Architecture Overview](/argis/architecture/design-overview)
- [Runtime Flow](/argis/architecture/runtime-flow)
- [Configurations](/argis/configurations/)
- [Glossary](./glossary)
