---
layout: default
title: Deployment Models
---

# Deployment models: local / cloud / hybrid

The key recommendation is to decouple ingestion from the detection core.

## 1) Local (offline)

Good for:

- security analysis, research, and offline replay
- environments that disallow network access

Usage:

- CLI: `phish-agent detect ...`
- Gradio: `python apps/demo/gradio_app.py`

## 2) Cloud (service)

Good for:

- backend detection service for gateways or security platforms

Suggested architecture:

- Ingestion layer: parse, redact, enrich org context
- Detection service: accept `EmailInput`, return JSON
- Event layer: push results to SIEM/SOAR

## 3) Hybrid

Good for:

- offline core with optional online evidence sources in isolation

Key points:

- online tools must be sandboxed with egress allowlists and timeouts
- online evidence should be additional `EvidenceStore` fields, not direct verdicts
