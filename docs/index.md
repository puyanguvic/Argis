---
layout: default
title: Phish Email Detection Agent Docs
---

# Phish Email Detection Agent Docs

This documentation hub covers the product and engineering design of the Phish Email Detection Agent, from threat context and system architecture to detection pipeline, reporting, and governance.

Core principles:

- **Evidence-first**: collect structured evidence (`EvidenceStore`) before scoring and rules, then produce findings and recommendations.
- **Deterministic by default**: prefer offline, deterministic tooling; models (if introduced) only provide evidence signals, not final verdicts.
- **No chain-of-thought**: explanations cite evidence keys and score breakdowns rather than exposing model reasoning.

## Documentation map

### 1) Overview

- [Problem statement](overview/problem-statement.html)
- [Threat landscape: phishing / BEC / APT](overview/threat-landscape.html)
- [Design goals and non-goals](overview/design-goals.html)

### 2) Architecture

- [System overview](architecture/system-overview.html)
- [Protocol v1 (UI <-> Engine contract)](protocol/v1.html)
- [Agent components](architecture/agent-components.html)
- [End-to-end workflow](architecture/workflow-pipeline.html)
- [Toolchain and external signals](architecture/toolchain.html)
- [Execution model](architecture/execution-model.html)

### 3) Agent

- [Roles: Reasoner / Executor / Verifier](agent/roles.html)
- [Decision logic and risk scoring](agent/decision-logic.html)
- [Reasoning policy and guardrails](agent/reasoning-policy.html)
- [Known failure modes](agent/failure-modes.html)

### 4) Skills (detection playbooks)

- [Skill mechanism overview](skills/overview.html)
- [Brand impersonation detection](skills/brand-impersonation.html)
- [BEC detection](skills/bec-detection.html)
- [URL analysis (redirects/obfuscation)](skills/url-analysis.html)
- [Header forensics](skills/header-forensics.html)
- [Attachment risk analysis](skills/attachment-analysis.html)

### 5) Detection pipeline

- [Ingestion: EML / MSG / API](pipeline/ingestion.html)
- [Parsing: MIME / header / body](pipeline/parsing.html)
- [Normalization and deobfuscation](pipeline/normalization.html)
- [Evidence collection](pipeline/evidence-collection.html)
- [Risk fusion and scoring](pipeline/risk-scoring.html)

### 6) Reporting

- [Reporting overview](reporting/overview.html)
- [Executive summary structure](reporting/executive-summary.html)
- [Evidence table schema](reporting/evidence-table.html)
- [Attack narrative](reporting/attack-narrative.html)
- [Recommendations](reporting/recommendation.html)
- [Machine-readable output: JSON / API](reporting/machine-output.html)

### 7) Policies

- [Security and access control](policies/security.html)
- [Privacy and redaction](policies/privacy.html)
- [Compliance (SOC2 / GDPR view)](policies/compliance.html)
- [Escalation policy](policies/escalation.html)

### 8) Evaluation

- [Metrics: precision / recall / risk](evaluation/metrics.html)
- [Benchmark scenarios](evaluation/benchmarks.html)
- [Known limitations](evaluation/limitations.html)

### 9) Deployment

- [Deployment models: local / cloud / hybrid](deployment/models.html)
- [Configuration: YAML / ENV](deployment/configuration.html)
- [Integrations: SIEM / email gateway](deployment/integration.html)
- [Operations and monitoring](deployment/operations.html)

### 10) Developer guide

- [Code structure](developer/code-structure.html)
- [Adding skills](developer/adding-skills.html)
- [Adding tools](developer/adding-tools.html)
- [Debugging and tracing](developer/debugging.html)

### 11) Governance

- [Model update policy](governance/model-updates.html)
- [Rule lifecycle](governance/rule-lifecycle.html)
- [Audit and traceability](governance/audit-traceability.html)

### 12) Glossary

- [Glossary](glossary.html)

## Start here

If you are new to the project, read in this order:

1. `overview/problem-statement.md`
2. `architecture/system-overview.md`
3. `pipeline/evidence-collection.md`
4. `reporting/overview.md`
