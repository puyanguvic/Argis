---
title: Execution Model
redirect_from:
  - /architecture/execution-model.html
---

# Single-run execution model (sandbox)

This page describes execution boundaries, budgets, and failure handling. The current implementation is single-process orchestration with deterministic tools, but the model anticipates future sandboxed integrations.

## Execution boundaries

- Offline by default: URL/domain tools do not do online resolution (`tools_builtin/url_analyzer.py`).
- Tools are treated as **pure functions**: input is `EmailInput` or derived data; output is serializable structured objects.
- All intermediate results flow into `EvidenceStore` for audit and replay (`schemas/evidence_schema.py`).

## Budgets and timeouts

Router provides a `PlanSpec` with:

- `budget_ms`: overall budget (logical budget for future use)
- `timeout_s`: per-run timeout (logical budget for future use)
- `fallback`: downgrade strategy (default `STANDARD`)

Current implementation does not enforce hard interrupts, but keeps this structure for future concurrent/isolated execution (`engine/router.py`, `engine/config.py`).

## Execution path and degradations

- Tools run in `plan.tools` order.
- When contextual escalation occurs (FAST → STANDARD), the system:
  - Writes `evidence.degradations += ["profile_escalated_contextual_signal"]`
  - Extends `plan.tools` and runs missing tools (`engine/orchestrator.py`)

If you introduce external tools or network intel, record degradations such as:

- Timeout, quota exhaustion, upstream unavailability
- Sandbox denial (network/file permissions)
- Partial results (incomplete evidence)

## Audit and replay

- `RunRecorder` writes JSONL per node with `node_name` and input state hash (`engine/recorder.py`).
- `replay_run()` merges JSONL into `EvidenceStore` and recomputes verdict (`engine/player.py`).

Audit goals:

- **Explainable**: answer “why this verdict.”
- **Reproducible**: same evidence and config yield the same decision.
- **Accountable**: identify which tool output or rule update changed behavior.
