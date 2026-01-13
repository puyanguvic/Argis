---
layout: default
title: Executive Summary
redirect_from:
  - /reporting/executive-summary.html
---

# Executive summary structure

A summary for non-technical stakeholders should answer:

1. **What happened**: is this likely phishing/BEC/malware delivery?
2. **How severe**: risk score and confidence?
3. **Why**: the top 2–3 evidence points?
4. **What to do next**: quarantine/escalate/notify guidance?

## Recommended summary fields

- Verdict: `ALLOW / ESCALATE / QUARANTINE`
- Risk score: `0–100`
- Confidence: `LOW / MED / HIGH`
- Profile: `FAST / STANDARD / DEEP`
- Top reasons: 3 max
- Recommended actions: 2–4 items
- Notes (optional):
  - “Evidence collection limited (FAST profile only)”
  - “BEC requires business verification”

## Mapping to current implementation

- Markdown report header covers most fields (`engine/report.py`).
- JSON output includes `verdict/risk_score/trace_id/profile/explanation` (`apps/cli/main.py`).
