---
layout: default
title: Adding Skills
redirect_from:
  - /developer/adding-skills.html
---

# Adding a skill

A skill becomes: new evidence sources (tools) + new evidence fields (schemas) + scoring/rules + docs/tests.

## Suggested steps

1. Define the attack type and observable evidence.
2. Extend `EvidenceStore`:
   - add fields and result models in `schemas/evidence_schema.py`
3. Implement evidence tools:
   - add a `*_analyzer.py` in `tools_builtin/`
   - ensure outputs are serializable (Pydantic model or dict)
4. Wire into routing and orchestration:
   - add tool to `_build_tool_map()` in `engine/orchestrator.py`
   - add tool names to profile tool lists (prefer `configs/profiles/balanced.yaml`)
5. Update scoring/rules:
   - add factors in `scoring/fusion.py` and weights in `configs/profiles/balanced.yaml`
   - or add hard rules in `scoring/rules.py`
6. Update reporting/explanations if needed:
   - add EvidenceLine entries in `engine/report.py`
7. Add tests and docs:
   - regression tests in `tests/`
   - doc page in `docs/skills/<your-skill>.md`

## Notes

- Prefer optional evidence sources over hard dependencies on upstream services.
- Online tools should be sandboxed with timeouts and quotas; failures should be recorded in `evidence.degradations`.
