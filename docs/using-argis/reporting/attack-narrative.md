---
title: Attack Narrative
redirect_from:
  - /reporting/attack-narrative.html
---

# Attack narrative

An attack narrative turns evidence into a readable story for analysts. It is **not** chain-of-thought and should never include unsupported speculation.

## Suggested narrative template

1. **Identity and trust**
   - Did SPF/DKIM/DMARC fail or misalign?
   - Is From/Reply-To inconsistent?
2. **Lure and intent**
   - Content intent (credential / oauth / invoice / malware)
   - Urgency or directive actions (click/download/reply)
3. **Landing and payload**
   - URLs to suspicious domains/shorteners/suspicious TLDs?
   - Macro or executable attachments?
4. **Potential impact**
   - Credential theft, permission abuse, financial loss, or malware execution
5. **Recommended actions**
   - Quarantine / escalate / notify / user guidance

## Current implementation status

The repo currently provides:

- Top reasons (max 3)
- Categorized evidence list

(`engine/report.py`) but does not generate a standalone narrative paragraph. If you add narrative output:

- Build from `EvidenceStore` + `score_breakdown` with templated sentences.
- Ensure every sentence maps to evidence fields or hard-rule codes.
