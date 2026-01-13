---
layout: default
title: Phish Email Detection Agent Docs
---

# Phish Email Detection Agent Docs

This documentation hub covers how to understand, run, configure, and track releases of Argis (Phish Email Detection Agent).

Core principles:

- **Evidence-first**: collect structured evidence (`EvidenceStore`) before scoring and rules, then produce findings and recommendations.
- **Deterministic by default**: prefer offline, deterministic tooling; models (if introduced) only provide evidence signals, not final verdicts.
- **No chain-of-thought**: explanations cite evidence keys and score breakdowns rather than exposing model reasoning.

## Documentation map

### 1) Get started

- [Get started](get-started/index.html)
- [Overview](get-started/overview/index.html)
- [Quickstart](get-started/quickstart.html)
- [Concepts](get-started/concepts/index.html)

### 2) Using Argis

- [Using Argis](using-argis/index.html)
- [CLI](using-argis/cli.html)
- [Gradio demo](using-argis/gradio-demo.html)
- [Connectors: IMAP/Gmail](using-argis/connectors/index.html)
- [Deployment](using-argis/deployment/index.html)
- [Reporting](using-argis/reporting/index.html)

### 3) Configuration

- [Configuration](configuration/index.html)
- [Config file](configuration/config-file.html)
- [Rules and weights](configuration/rules.html)
- [Skills](configuration/skills/index.html)
- [Extending Argis](configuration/extending/index.html)

### 4) Releases

- [Releases](releases/index.html)
- [Changelog](releases/changelog.html)
- [Feature maturity](releases/feature-maturity.html)
- [Open source](releases/open-source.html)

## Start here

If you are new to the project, read in this order:

1. `get-started/overview/problem-statement.md`
2. `get-started/concepts/architecture/system-overview.md`
3. `get-started/concepts/pipeline/evidence-collection.md`
4. `using-argis/reporting/overview.md`
