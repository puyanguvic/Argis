---
title: Recommendations
redirect_from:
  - /reporting/recommendation.html
---

# Recommendations

This page outlines default handling per verdict and when stronger human workflows are required.

## 1) `benign` (ALLOW)

Recommended actions:

- deliver normally
- if profile is FAST with limited evidence, remind users to verify unexpected requests out-of-band

Typical scenarios:

- no auth failures, no suspicious URLs, no malicious intent, no attachment risk

## 2) `suspicious` (ESCALATE / WARN)

Recommended actions:

- trigger human review (security team or tier-2)
- warn users: do not click links, share credentials, or execute attachments
- for BEC: verify via non-email channels (phone/IM/ticketing)

Typical scenarios:

- partial risk signals without hard-rule confidence
- insufficient org context (contacts, threads, finance workflow)

## 3) `phishing` (QUARANTINE)

Recommended actions:

- quarantine email, block link clicks, prevent attachment execution
- raise an incident and notify users and security team
- if brand impersonation or auth failure: consider gateway rules/IOCs

Typical scenarios:

- hard rules matched (`EvidenceStore.hard_rule_matches` not empty)
- risk score exceeds `block_threshold`
