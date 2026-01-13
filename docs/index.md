---
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

- [Get started](get-started/index.md)
- [Overview](get-started/overview/index.md)
- [Quickstart](get-started/quickstart.md)
- [Concepts](get-started/concepts/index.md)

### 2) Using Argis

- [Using Argis](using-argis/index.md)
- [CLI](using-argis/cli.md)
- [Gradio demo](using-argis/gradio-demo.md)
- [Connectors: IMAP/Gmail](using-argis/connectors/index.md)
- [Deployment](using-argis/deployment/index.md)
- [Reporting](using-argis/reporting/index.md)

### 3) Configuration

- [Configuration](configuration/index.md)
- [Config file](configuration/config-file.md)
- [Rules and weights](configuration/rules.md)
- [Skills](configuration/skills/index.md)
- [Extending Argis](configuration/extending/index.md)

### 4) Releases

- [Releases](releases/index.md)
- [Changelog](releases/changelog.md)
- [Feature maturity](releases/feature-maturity.md)
- [Open source](releases/open-source.md)

## Start here

If you are new to the project, read in this order:

1. `get-started/overview/problem-statement.md`
2. `get-started/concepts/architecture/system-overview.md`
3. `get-started/concepts/pipeline/evidence-collection.md`
4. `using-argis/reporting/overview.md`
