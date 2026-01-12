---
layout: default
title: Threat Landscape
---

# Threat landscape: phishing / BEC / targeted email

This page maps email threats to observable evidence. The system avoids single-signal decisions and instead decomposes attacks into measurable dimensions.

## 1) Common attack types

### Credential phishing

- Lures users to login pages or asks for passwords/MFA codes.
- Typical indicators: brand-impersonation domains, shorteners, suspicious TLDs, IP hosts, login-related keywords.

### BEC / financial fraud

- Impersonates executives or vendors to request transfers or invoice changes.
- Typical indicators: Reply-To spoofing, display-name deception, urgency language, invoice/payment keywords.

### OAuth consent and collaboration abuse

- Tricks users into granting app permissions or sharing access.
- Often has fewer classic “malicious” signals, but strong semantic intent and brand context.
- These signals are used for **context escalation (FAST → STANDARD)** rather than direct scoring (see `engine/orchestrator.py`).

### Malware delivery

- Uses macro documents, scripts, or executable attachments.
- Common patterns: “Enable Content” prompts, script attachments, nested archives (no unpacking by default).

### Targeted spear phishing / APT

- High-quality writing, strong organizational context, may use compromised legitimate accounts.
- Weak hard signals, requiring multi-signal fusion and human review paths.

## 2) Observable evidence dimensions (tools)

- **Header authentication**: SPF/DKIM/DMARC results and alignment (`tools_builtin/header_analyzer.py`).
- **URL and domain signals**: shorteners, suspicious TLDs, IP hosts, login keywords, redirect chains (`tools_builtin/url_analyzer.py`).
- **Domain similarity**: brand lookalikes, homoglyphs, punycode (`tools_builtin/domain_risk.py`).
- **Semantic intent**: credential/invoice/OAuth/malware intent and urgency (`tools_builtin/content_analyzer.py`).
- **Attachment metadata**: macro and executable extensions (`tools_builtin/attachment_analyzer.py`).

## 3) Why evidence-first helps defenders

- **Explainable**: risk is decomposed into explicit evidence items and score contributions.
- **Controllable**: offline, deterministic defaults avoid production drift.
- **Evolvable**: new intel or models become additional evidence sources without changing verdict logic.
