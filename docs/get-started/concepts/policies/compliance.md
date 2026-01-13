---
layout: default
title: Compliance (SOC2 / GDPR)
redirect_from:
  - /policies/compliance.html
---

# Compliance (SOC2 / GDPR perspective)

This page provides engineering guidance for compliance alignment. It is not legal advice nor a certification claim.

## 1) SOC2 (security / availability / confidentiality)

- **Security**: least-privilege runtime, egress controls, dependency/supply-chain management
- **Availability**: health checks, timeouts, backoff, capacity planning
- **Confidentiality**: data classification, encryption at rest, access audits, retention policies
- **Change management**: review workflow for rules/weights/models with rollback

## 2) GDPR (data protection)

- **Data minimization**: do not retain full email bodies by default; store only evidence needed for detection
- **Purpose limitation**: use data solely for security detection and response
- **Retention**: set retention by incident severity (see `get-started/concepts/policies/privacy.md`)
- **Access control and audit**: audit access to JSONL/events and enforce least privilege

## 3) Suggested engineering checklist

- Add `schema_version` and `config_version/config_hash` in integrations
- Track rule/weight changes (see `configuration/rules.md`)
- Provide redaction strategies for sensitive fields (URLs, email addresses, body excerpts)
- Define DPAs/vendor assessments if external intel/models are used
