---
layout: default
title: Glossary
---

# Glossary

## Email / threat

- **Phishing**: email attacks that trick users into clicking links, submitting credentials, or taking malicious actions.
- **BEC (Business Email Compromise)**: impersonation to drive transfers or payment detail changes.
- **APT**: advanced, persistent, low-noise targeted campaigns.

## Email authentication

- **SPF**: sender IP authorization for a domain.
- **DKIM**: signature-based integrity and domain validation.
- **DMARC**: policy framework combining SPF/DKIM with alignment and disposition.
- **Alignment**: whether auth results align to the From domain. This project uses a simplified rule (`tools_builtin/header_analyzer.py`).

## System concepts

- **EmailInput**: normalized email input schema (`schemas/email_schema.py`).
- **EvidenceStore**: evidence bus for tool outputs (`schemas/evidence_schema.py`).
- **Tool**: component that converts input into structured evidence (`tools_builtin/`).
- **Profile (FAST/STANDARD/DEEP)**: investigation depth/cost routing (`engine/router.py`).
- **Hard rule**: rule that forces `phishing` when matched (`scoring/rules.py`).
- **Risk fusion / risk score**: weighted aggregation into 0–100 (`scoring/fusion.py`).
- **Verdict**: discrete decision `benign` / `suspicious` / `phishing`.
- **Recommended action**: `allow` / `warn` / `quarantine` (`engine/explanation.py`).
- **Contextual escalation**: FAST → STANDARD upgrade to gather more evidence for collaboration/OAuth cases (`engine/orchestrator.py`).
- **Degradations**: list of downgrade/missing-evidence/escalation flags (`EvidenceStore.degradations`).
