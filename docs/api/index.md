---
title: API
description: Integration guide for the Argis HTTP API, including request model, runtime guarantees, response metadata, and migration paths.
---

# API

Use this section when you are integrating Argis into services, workers, queues, or internal tooling. It separates caller-facing API behavior from the broader product guides.

<p class="docs-lead">The API pages are written for engineers responsible for reliable integration, not just endpoint discovery. They focus on request shape, trust-boundary rules, degraded execution semantics, and the runtime metadata you need for operations and audits.</p>

## API Mental Model

The HTTP API is a delivery interface over the orchestrator, not a separate inference product. API responses preserve the same deterministic-first design as the core runtime:

- input is normalized and validated
- evidence is built before any optional judge step
- degraded conditions produce fallback output instead of silent null behavior
- API responses carry runtime metadata so operators can explain what happened

## Start Here

<div class="docs-grid">
  <a class="docs-card" href="./guides-concepts">
    <div class="docs-card-title">Guides and Concepts</div>
    <p class="docs-card-text">Integration patterns, runtime interpretation, and caller-side operating advice.</p>
  </a>
  <a class="docs-card" href="./reference">
    <div class="docs-card-title">API Reference</div>
    <p class="docs-card-text">Request fields, response shape, runtime metadata, fallback semantics, and validation errors.</p>
  </a>
  <a class="docs-card" href="./contract">
    <div class="docs-card-title">API Contract</div>
    <p class="docs-card-text">Stable low-level transport and boundary contract for <code>POST /analyze</code>.</p>
  </a>
  <a class="docs-card" href="./migration-guide">
    <div class="docs-card-title">Migration Guide</div>
    <p class="docs-card-text">Upgrade guidance when caller-visible behavior or evidence defaults change.</p>
  </a>
</div>

## Entry Points

- Primary endpoint: `POST /analyze`
- Health endpoint: `GET /health`

## What The API Guarantees

- request bodies must be explicit and schema-like rather than inferred from arbitrary object shapes
- API mode rejects local filesystem input patterns such as `eml_path`
- attachment identifiers must be logical names, not paths
- evidence is sanitized by default for API consumers
- runtime metadata makes fallback and capability state observable

<div class="section-note">
  <p>The most common integration mistake is treating HTTP <code>200</code> as proof that the normal judge-assisted path was used. In Argis, a degraded fallback response is still a valid response, and must be interpreted through <code>provider_used</code> and <code>fallback_reason</code>.</p>
</div>

## What This Section Covers

- how to send plain-text and structured JSON inputs
- which input modes are allowed in API context
- what response metadata is stable and useful for observability
- how fallback behavior and evidence sanitization show up in results

## Related Product Docs

- [Using Argis: App](/argis/using-argis/app)
- [Operations: Runbook](/argis/operations/runbook)
- [Operations: Security Boundary](/argis/operations/security-boundary)

## Next Reading

- Start with [Guides and Concepts](./guides-concepts) if you need integration patterns and operating advice.
- Go straight to [API Reference](./reference) if you are wiring the endpoint now.
- Read [Migration Guide](./migration-guide) if you are upgrading an existing caller.
