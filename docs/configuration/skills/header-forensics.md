---
title: Header Forensics
redirect_from:
  - /skills/header-forensics.html
---

# Header forensics

Header forensics evaluates sender authenticity and signs of spoofing or misalignment.

## Core signals

- SPF/DKIM/DMARC: pass/fail/none
- Alignment: whether auth results align to the From domain (simplified)
- Anomalies: missing headers or missing auth results

## Current implementation

Tool: `header_auth_check(raw_headers)` (`tools_builtin/header_analyzer.py`)

- Regex extraction of `spf|dkim|dmarc=(pass|fail|none)`
- Simplified alignment:
  - DMARC pass, or SPF pass **and** DKIM pass
- `anomalies`:
  - `missing_headers`
  - `missing_auth_results`

## Routing/scoring integration

- Router runs header checks first and includes results in `preliminary_score` (`engine/router.py`).
- Fusion factors: `spf_fail`, `dkim_fail`, `dmarc_fail` (`scoring/fusion.py`).

## Reporting guidance

When auth fails or misaligns, highlight:

- failing items (SPF/DKIM/DMARC)
- alignment status (`aligned=false`)
- increased priority if combined with login keywords or lookalike domains
