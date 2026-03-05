---
title: Rules
description: Where Argis routing, scoring, validation, trust-boundary, and fallback rules live, and how to change them responsibly.
---

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

## What Counts As A Rule

In this project, a rule is not just a threshold. It can be:

- a dependency boundary
- a scoring heuristic
- a route selection threshold
- a judge eligibility decision
- an API validation constraint
- a fallback or output-validation guardrail

That is why rule changes often require both code and documentation updates.

## Examples Of Rule Families

### Pre-score and routing rules

These determine when content stays in `allow`, moves to `review`, or escalates to `deep`.

### Judge rules

These determine whether the judge runs at all, especially for `allow` routes under `never`, `sampled`, or `always` modes.

### Boundary rules

These are the API constraints that reject `eml_path`, path-like attachments, or invalid request shapes.

### Validation rules

These guard the final result shape, verdict values, score range, and minimum evidence expectations for phishing outputs.

## Change Discipline

When you change rules:

- document the operator-visible behavior change
- update tests that cover the affected route, threshold, or validation behavior
- treat threshold shifts as policy changes, not invisible internal tuning

Architecture details:

- [Design Overview](/argis/architecture/design-overview)
- [Runtime Flow](/argis/architecture/runtime-flow)
