---
layout: default
title: Skills and Playbooks Overview
redirect_from:
  - /skills/overview.html
---

# Skill / playbook mechanism

A **skill/playbook** is a bundle of *evidence steps (tools) + evidence schema + decision policy* focused on a specific attack class.

Today the repository behaves more like a fixed set of playbooks selected by the Router (FAST/STANDARD/DEEP), but the docs keep the skill framing for future composition.

## Minimum components of a skill

1. **Trigger conditions**: when it runs (route thresholds, contextual escalation, manual trigger)
2. **Evidence sources**: tools to execute and fields to collect (`EvidenceStore`)
3. **Scoring/rules**: scoring factors or hard rules contributed by this skill
4. **Presentation**: how the report explains and recommends actions

## Mapping skills to code

| Skill | Primary evidence | Primary implementation |
| --- | --- | --- |
| Header Forensics | SPF/DKIM/DMARC, alignment, anomalies | `tools_builtin/header_analyzer.py`, `engine/router.py` |
| URL Analysis | final_domain, shortener, suspicious_tld, login_keywords, ip_host | `tools_builtin/url_analyzer.py`, `tools_builtin/url_utils.py` |
| Brand Impersonation | lookalike/homoglyph/punycode | `tools_builtin/domain_risk.py`, `scoring/rules.py` |
| Attachment Analysis | macro/executable extensions | `tools_builtin/attachment_analyzer.py` |
| BEC Detection | Reply-To mismatch, payment intent, urgency | `engine/router.py`, `tools_builtin/content_analyzer.py` |

## Composition and routing (FAST/STANDARD/DEEP)

- FAST: minimal evidence set for low-risk or resource-constrained cases
- STANDARD: adds URL evidence
- DEEP: adds domain similarity and attachment risk

Profiles and tool sets are configured in `configs/profiles/balanced.yaml` (`engine/config.py`).

## Extension guidance

For new skills (e.g., account takeover, historical behavior anomalies):

- Define the output evidence structure first (`schemas/evidence_schema.py`).
- Adapt external signals into deterministic evidence sources (write into `EvidenceStore`).
- Add factors to `scoring/fusion.py` and weights in config, or add hard rules in `scoring/rules.py`.
