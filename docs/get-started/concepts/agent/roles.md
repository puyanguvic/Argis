---
title: Roles: Reasoner / Executor / Verifier
redirect_from:
  - /agent/roles.html
---

# Reasoner / Executor / Verifier

Although the current implementation is single-process, responsibilities map to three roles that scale to more complex agent architectures.

## 1) Reasoner (planning / routing)

Responsibilities:

- Extract quick signals and estimate risk vs. investigation cost.
- Select the path (FAST/STANDARD/DEEP).
- Produce a structured execution plan `PlanSpec`.

Implementation:

- `engine/router.py` (`quick_features()`, `preliminary_score()`, `plan_routes()`).

## 2) Executor (tool execution / evidence)

Responsibilities:

- Run tools per plan and convert raw input into structured evidence.
- Handle degradations, retries, or supplementation (future).

Implementation:

- `engine/orchestrator.py` (tool execution, contextual escalation)
- `tools_builtin/` (deterministic evidence sources)

## 3) Verifier (decision / explanation / output)

Responsibilities:

- Apply hard rules and risk fusion to produce verdicts.
- Generate structured explanations (evidence references + score breakdowns).
- Render reports/JSON for humans and systems.

Implementation:

- `engine/policy.py` + `scoring/`
- `engine/explanation.py` + `schemas/explanation_schema.py`
- `engine/report.py`, `apps/cli/main.py`

## Why split roles

- **Auditable**: planning, evidence, and decisions can be recorded and replayed.
- **Replaceable**: swap tools or planners without changing the decision contract.
- **Controlled risk**: keep explanation/output decoupled from tools and external dependencies.
