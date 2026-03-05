---
layout: home
title: Argis Docs

hero:
  name: Argis Docs
  text: Deterministic-first phishing email detection
  tagline: Product guides, API contracts, architecture references, and operational playbooks for running Argis with bounded side effects and evidence-backed outputs.
  actions:
    - theme: brand
      text: Start with Quickstart
      link: /argis/getting-started/quickstart
    - theme: alt
      text: Explore Product Docs
      link: /argis/
    - theme: alt
      text: Read the API Docs
      link: /api/

features:
  - title: Product Guides
    details: Start locally, choose between CLI and API workflows, and configure runtime behavior without crossing trust boundaries.
  - title: Architecture
    details: Understand the policy, tools, and orchestrator layers that keep Argis explicit, auditable, and deterministic by default.
  - title: Operations
    details: Monitor fallback behavior, keep evidence handling safe, and ship releases against documented quality gates.
---

## What Argis Is

Argis is a phishing email detection system designed around a deterministic-first control stack. It can evaluate plain text, structured JSON payloads, and EML-derived content, then return a verdict, a bounded risk score, evidence-backed indicators, and runtime metadata that explain how the result was produced.

It is built for environments where explainability and operating discipline matter as much as raw detection performance. The online path favors explicit heuristics, bounded side effects, and validation over opaque end-to-end model behavior.

## Core Operating Model

- Deterministic evidence building happens before any optional remote model involvement.
- Risky outcomes are expected to remain tied to indicators and evidence payloads.
- Remote judge usage is policy-controlled and may be bypassed entirely.
- If remote execution is unavailable or fails, the system emits deterministic fallback output instead of failing closed.
- API mode keeps stricter trust boundaries than local CLI mode.

## Read By Role

### New to the project

- [Overview](/argis/getting-started/overview)
- [Quickstart](/argis/getting-started/quickstart)
- [Explore](/argis/getting-started/explore)
- [Glossary](/argis/getting-started/glossary)

### Integrating the HTTP API

- [API Overview](/api/)
- [Guides and Concepts](/api/guides-concepts)
- [API Reference](/api/reference)
- [Migration Guide](/api/migration-guide)

### Operating or extending the system

- [Configurations](/argis/configurations/)
- [Architecture](/argis/architecture/)
- [Operations](/argis/operations/)

<div class="journey-grid">
  <div class="journey-card">
    <h3>Product and workflow</h3>
    <p>Start with product behavior, local usage, and configuration before moving into operating detail.</p>
  </div>
  <div class="journey-card">
    <h3>API integration</h3>
    <p>Focus on request shape, trust-boundary rules, runtime metadata, and fallback semantics.</p>
  </div>
  <div class="journey-card">
    <h3>Architecture and policy</h3>
    <p>Review the evidence-first control stack, routing logic, and operational guarantees.</p>
  </div>
</div>

## Recommended Reader Journeys

### I need to evaluate the product quickly

Read [Overview](/argis/getting-started/overview), then [Quickstart](/argis/getting-started/quickstart), then [Using Argis](/argis/using-argis/).

### I need to integrate the API safely

Read [API](/api/), then [API Reference](/api/reference), then [Security Boundary](/argis/operations/security-boundary), then [Runbook](/argis/operations/runbook).

### I need to review architecture or policy design

Read [Concepts](/argis/getting-started/concepts), then [Design Overview](/argis/architecture/design-overview), then [Runtime Flow](/argis/architecture/runtime-flow), then [Rules](/argis/configurations/rules).

## Documentation Map

<div class="docs-grid">
  <a class="docs-card" href="/argis/">
    <div class="docs-card-title">Argis</div>
    <p class="docs-card-text">Product behavior, usage workflows, runtime controls, and operational guidance.</p>
  </a>
  <a class="docs-card" href="/api/">
    <div class="docs-card-title">API</div>
    <p class="docs-card-text">Integration guidance, wire contract, request and response expectations, and migration notes.</p>
  </a>
  <a class="docs-card" href="/argis/architecture/">
    <div class="docs-card-title">Architecture</div>
    <p class="docs-card-text">Control-stack design, evidence building, route selection, judge behavior, and validation flow.</p>
  </a>
  <a class="docs-card" href="/argis/operations/">
    <div class="docs-card-title">Operations</div>
    <p class="docs-card-text">Runbooks, observability, trust-boundary constraints, release discipline, and docs standards.</p>
  </a>
</div>

## Key Terms

If you are new to the Argis vocabulary, read the [Glossary](/argis/getting-started/glossary) early. Terms such as `EvidencePack`, `precheck`, `route`, `path`, `judge`, and `fallback` have specific meanings in this codebase and should not be read loosely.

<div class="section-note">
  <p>The most important mental shift in this documentation set is that Argis is described as a controlled runtime, not as an undifferentiated “AI agent” box. Pages are organized around boundaries, evidence, routing, and operator-visible behavior.</p>
</div>

## Canonical Structure

The documentation site now uses `/argis/` and `/api/` as the primary information architecture. The earlier root-level compatibility pages have been removed so the site has a single canonical structure.

## What To Expect From The Docs

These docs are written to match the implementation, not an aspirational roadmap. Pages in this site should answer at least one of these questions clearly:

- what the system does
- what a caller or operator must provide
- what output to expect
- what runtime guarantees and boundaries exist
- which knobs are policy or configuration, and which are part of the public contract

## Current Focus

Recent documentation work has focused on:

- making the `/argis/` section the primary product documentation path
- separating product docs from API docs and blog content
- replacing legacy compatibility pages with a single canonical structure
- expanding core product, architecture, and API pages into implementation-backed documentation

For release-level details, see the [v0.1.1 release page](https://github.com/puyanguvic/Argis/releases/tag/v0.1.1) and [CHANGELOG.md](https://github.com/puyanguvic/Argis/blob/main/CHANGELOG.md).
