---
layout: default
title: Reporting Overview
---

# Reporting overview

Reports should be **actionable, explainable, and auditable**:

- Actionable: clear recommended actions (allow/warn/quarantine)
- Explainable: top reasons and evidence details
- Auditable: traceable to `EvidenceStore` and score factors

Two outputs are provided:

- **Markdown report**: for human readers (`engine/report.py`)
- **JSON output**: for integrations (`apps/cli/main.py --format json`)

## Markdown report structure (current)

`engine/report.py` produces:

1. Header and summary:
   - Verdict label (ALLOW / ESCALATE / QUARANTINE)
   - Confidence (derived from score)
   - Trace ID
   - Profile (FAST/STANDARD/DEEP)
2. Top reasons: up to 3 ordered by severity/contribution
3. Recommended actions: aligned to verdict
4. Evidence details: grouped by category (auth/URL/content/attachments)
5. Runtime: total duration

## Structured explanation output

`engine/explanation.py` generates structured explanations for:

- API responses
- SIEM event fields
- audit/replay stability
