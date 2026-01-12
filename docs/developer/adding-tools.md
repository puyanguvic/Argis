---
layout: default
title: Adding Tools
---

# Adding tools

A tool is a pure component that turns inputs into structured evidence.

## 1) Design the output schema

- add result models in `schemas/evidence_schema.py`
- add optional fields in `EvidenceStore`

## 2) Implement the tool

- add a module under `tools_builtin/` (e.g., `tools_builtin/whois_lookup.py`)
- accept only necessary inputs (domain/URL/attachment metadata)
- return schema models or dicts that are JSON serializable

## 3) Wire into the plan

Tools are referenced by string name in `PlanSpec.tools`, mapped in:

- `engine/orchestrator.py` → `_build_tool_map()`
- `engine/orchestrator.py` → `_assign_observation()`

Also update:

- `configs/profiles/balanced.yaml` to include the tool in profile lists

## 4) Scoring and reporting hooks

- add factors in `scoring/fusion.py` and weights in config
- add EvidenceLine entries in `engine/report.py` (optional)

## 5) Tool safety (especially online tools)

- enforce timeouts and maximum output size
- define explicit egress allowlists (if network required)
- ensure outputs are auditable and avoid leaking sensitive content
