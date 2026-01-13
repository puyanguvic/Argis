---
title: Privacy Policy
redirect_from:
  - /policies/privacy.html
---

# Privacy and redaction

Email content often includes PII and sensitive business data. The design follows **data minimization, need-to-know retention, and auditability**.

## 1) Data minimization

- Core decisions rely on structured evidence (`EvidenceStore`), not full email bodies.
- Structured explanations (`Explanation`) exclude `body_text/body_html` by default.

## 2) Logs and JSONL recording

When `--record run.jsonl` is enabled:

- tool outputs are recorded (may include URLs, domains, attachment hashes)
- the input state is not written in cleartext, only hashed (`input_state_hash`)

Recommendations:

- treat `run.jsonl` as sensitive audit data with access control and retention policy
- in production, redact URLs (e.g., keep domain only or hash), and trim fields per compliance

## 3) Retention and deletion (guidance)

- `benign`: short retention for false-positive analysis, then delete
- `suspicious/phishing`: retain per incident response and compliance needs
- for GDPR or similar, provide deletion/export capability in integration layers

## 4) Third-party integration boundaries

If online intel or models are introduced:

- document exactly what fields are sent outside (egress), minimize to domains/hashes
- use tenant isolation and access auditing
- document enable/disable toggles and defaults
