---
layout: default
title: Escalation Policy
---

# Escalation policy

When evidence is insufficient for automatic blocking or when decisions require org context, trigger human escalation to reduce false positives/negatives.

## 1) Recommended automatic escalation triggers

- verdict is `suspicious`
- profile is `FAST` and risk signals exist (limited evidence)
- any high-risk intent/action:
  - credential theft or login prompts (`semantic.intent == "credential_theft"`)
  - OAuth/permissions/delegation requests (collaboration intents)
  - payment/transfer/change of bank details (e.g., `invoice_payment`)
- auth-failure combos:
  - DMARC fail + Reply-To mismatch + login URL (hard-rule pattern)
- org policy triggers:
  - new contact / first-time sender domain (provided by integration layer)

## 2) Human review checklist

- verify sender identity (directory/history/IM/phone)
- inspect URLs in an isolated environment (look for login forms and brand markers)
- if attachments exist: sandboxed static/dynamic analysis and IOC extraction
- for BEC: verify payment changes through approved finance workflow

## 3) Triage guidance

- `suspicious`: default to “quarantine then review” or “warn and gray release,” depending on tolerance
- `phishing`: quarantine + incident response (notify, hunt, block IOCs)
