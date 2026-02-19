# AGENTS.md

This document defines engineering rules for AI coding agents working in this repository.
Scope: repository root and all subdirectories.

## 1. Purpose

This project is a phishing detection system with a layered architecture.
The primary goals are:

1. Deterministic and auditable analysis by default.
2. Clear separation between policy, execution, and orchestration.
3. Safe runtime behavior with bounded side effects.
4. Controlled migrations with explicit deprecation plans.

## 2. Architecture Model

### 2.1 Layered Design

The codebase follows a control-stack architecture:

1. `policy` (Policy Layer)
2. `tools` (Execution Layer)
3. `orchestrator` (Control Stack + Stage Primitives)
4. Delivery Interfaces (`api`, `ui`, `cli`)

### 2.2 Layer Responsibilities

#### `policy` - Policy Layer
- Paths:
  - `src/phish_email_detection_agent/policy/`
  - local installable skillpack folders: `skillpacks/*/SKILL.md`
- Responsibility:
  - What to do and in what order.
  - Fixed skill-chain metadata and policy priors.
- Must not:
  - Perform direct side-effectful execution (network fetch, attachment parsing, etc.).

#### `tools` - Execution Layer
- Path: `src/phish_email_detection_agent/tools/`
- Responsibility:
  - Deterministic capability execution (URL/domain/header/attachment/OCR/ASR/text).
  - Stable callable tools for runtime registration.
- Requirements:
  - New built-in tools must be reflected in tool catalog/registry and test coverage.

#### `orchestrator` - Control Stack
- Path: `src/phish_email_detection_agent/orchestrator/`
- Responsibility:
  - Runtime wiring and flow control.
  - Precheck scoring rules.
  - Skill routing.
  - Tool execution wrappers and retries.
  - Evidence identity/trace references.
  - Online validation and offline evaluation.
- Current modules:
  - `pipeline.py`, `precheck.py`, `skill_router.py`, `pipeline_policy.py`,
    `verdict_routing.py`, `tool_executor.py`, `evidence_store.py`,
    `validator.py`, `evaluator.py`
- Stage primitives:
  - `orchestrator/stages/evidence_stage.py`
  - `orchestrator/stages/evidence_builder.py`
  - `orchestrator/stages/executor.py`
  - `orchestrator/stages/judge.py`
  - `orchestrator/stages/runtime.py`

## 3. Dependency Direction Rules

Allowed dependency direction:

1. `policy` -> `domain` (and lightweight policy/config types)
2. `tools` -> `domain`, `infra`
3. `orchestrator` -> `policy`, `tools`, `domain`, `providers`
4. `api/ui/cli` -> `orchestrator`

Disallowed patterns:

1. `tools` importing `policy` logic.
2. `policy` invoking side-effectful tool behavior directly.
3. High-level package `__init__.py` files causing eager circular imports.

Use lazy exports when package aggregation introduces cycle risk.

## 4. Runtime Flow Contract

The runtime flow is expected to remain explicit and observable:

1. Input parse and normalization.
2. Evidence construction (deterministic precheck path).
3. Skill routing (allow/review/deep decisions).
4. Optional judge pass (remote model).
5. Online validation of final output.
6. Final result emission with evidence and runtime metadata.

All high-risk outcomes should remain evidence-backed.

## 5. Evidence and Traceability

Evidence must be machine-referenceable:

1. Keep stable `evidence_id` style references where possible.
2. Preserve source and category metadata.
3. Avoid opaque conclusions without supporting indicators.
4. Ensure output payloads are reproducible from deterministic inputs whenever feasible.

## 6. Judge and Evaluation Policy

Online path:

1. Judge output is merged with deterministic pre-score using calibration logic.
2. Online validator checks verdict/risk shape and minimum evidence expectations.
3. Validation issues must be represented in output or handled by fallback behavior.

Offline path:

1. Use evaluator modules for dataset-level metrics and regression tracking.
2. Keep experimental metrics out of online inference codepaths.

## 7. API Stability and Migrations

When refactoring public module paths:

1. Prefer direct migration when impact is local and tests/docs are updated in the same change.
2. Use temporary compatibility re-exports only when an external/public integration requires them.
3. Every temporary compatibility layer must include a concrete removal milestone.
4. Avoid breaking API response keys unless explicitly requested.
5. Remove expired compatibility layers promptly to reduce architectural drift.

## 8. Security and Safety Baseline

1. Keep dangerous capabilities opt-in by default.
2. Enforce bounded fetch behavior (timeouts, redirects, max bytes).
3. Do not silently loosen private network restrictions.
4. Do not add unbounded retries or uncontrolled external execution.

## 9. Quality Gates

Run these before considering a change complete:

```bash
uv sync
ruff check src tests docs scripts
pytest -k 'not hf_phishing_email_balanced_sample'
```

Recommended targeted checks for architecture changes:

```bash
pytest tests/orchestrator/test_control_stack.py
pytest tests/orchestrator/test_text_prescore.py tests/orchestrator/test_pipeline_smoke.py
```

## 10. Definition of Done

A change is done only if all are true:

1. Architecture boundaries are preserved.
2. No import-cycle regressions were introduced.
3. Relevant tests were added/updated and pass.
4. `README.md` and `docs/architecture.md` reflect behavior changes.
5. Deprecated or compatibility-only code introduced by the change is tracked and time-bounded.

## 11. Prohibited Changes

1. Adding indefinite compatibility layers without removal criteria.
2. Skipping test/doc updates when behavior or interfaces change.
3. Mixing policy decisions into tool implementations.
4. Mixing experimental offline evaluation logic into online serving flow.
5. Introducing broad, implicit side effects in control-layer code.
