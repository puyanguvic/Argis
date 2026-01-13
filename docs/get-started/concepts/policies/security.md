---
layout: default
title: Security Policy
redirect_from:
  - /policies/security.html
---

# Security and access control

The baseline is **least privilege + offline reproducibility**: tools do not require network access by default, attachments are never executed, and decisions are based on structured evidence only.

## 1) Default security boundaries

- **No network by default**: URL/domain analysis is offline (`tools_builtin/url_analyzer.py`).
- **No execution or unpacking**: attachment analysis is metadata-only (`tools_builtin/attachment_analyzer.py`).
- **Auditable**: JSONL record and replay supported (`engine/recorder.py`, `engine/player.py`).

## 2) Permissions and isolation (production)

When deploying as a service:

- run under a non-privileged account
- separate ingestion (parsing/decoding/redaction) from detection core (evidence/decision)
- if online tools are introduced, isolate them:
  - egress allowlists
  - timeouts and concurrency limits
  - schema validation and output size limits

## 3) Configuration and secrets

Core flow does not require external secrets today. If external intel or models are added:

- inject via environment variables or secret managers
- avoid logging secrets in logs/reports/JSONL
- track configuration versions (record config hash)

An `.env.example` exists as a placeholder for future extensions.

## 4) Secure output principles

- Explanations exclude full email bodies (structured evidence only).
- Reports for humans should avoid clickable live links (use redaction in production).
- For `phishing`, default to blocking links and attachment downloads.
