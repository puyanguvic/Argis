# Rules

Argis behavior is controlled by explicit rules in policy and orchestrator components.

## Where Rules Live

- policy priors and heuristics: `src/phish_email_detection_agent/policy/`
- precheck and routing: `src/phish_email_detection_agent/orchestrator/precheck.py`, `skill_router.py`
- pipeline policy and verdict routing: `pipeline_policy.py`, `verdict_routing.py`
- execution and retry wrappers: `tool_executor.py`, `stages/executor.py`
- output validation: `validator.py`

## Rule Objectives

- deterministic-first scoring and routing
- bounded side effects and retries
- evidence-backed outcomes for risky verdicts
- stable output shape for callers

Architecture details: [Design](/design).
