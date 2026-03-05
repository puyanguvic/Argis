---
title: Operations
description: Operational guidance for running Argis in production-like environments, including observability, runbooks, trust boundaries, and release gates.
---

# Operations

This section covers runtime operation and production-readiness guidance.

<p class="docs-lead">Operations pages are written for the people who need to keep the system understandable under load, during incidents, and across releases. They are about runtime signals, boundary decisions, and change discipline as much as about commands.</p>

## What This Section Covers

Operations documentation is about keeping Argis understandable under real runtime conditions. It focuses on:

- how to triage incidents quickly
- which signals to monitor continuously
- where the API trust boundary is intentionally strict
- which checks are required before shipping behavior changes

## In This Section

<div class="docs-grid">
  <a class="docs-card" href="./runbook">
    <div class="docs-card-title">Runbook</div>
    <p class="docs-card-text">First-response procedures for request validation failures, fallback spikes, and evidence-detail issues.</p>
  </a>
  <a class="docs-card" href="./observability">
    <div class="docs-card-title">Observability</div>
    <p class="docs-card-text">Metrics, logs, dashboards, and the high-signal fields worth tracking.</p>
  </a>
  <a class="docs-card" href="./security-boundary">
    <div class="docs-card-title">Security Boundary</div>
    <p class="docs-card-text">How API mode and CLI mode differ, and why those trust assumptions must stay separate.</p>
  </a>
  <a class="docs-card" href="./release-gates">
    <div class="docs-card-title">Release Gates</div>
    <p class="docs-card-text">Checks for testing, documentation, API compatibility, and safety before shipping changes.</p>
  </a>
  <a class="docs-card" href="./docs-style-guide">
    <div class="docs-card-title">Docs Style Guide</div>
    <p class="docs-card-text">Standards for keeping the documentation set implementation-backed, consistent, and maintainable.</p>
  </a>
</div>

## Recommended Reading Order

1. Read [Security Boundary](./security-boundary) if Argis will receive untrusted input.
2. Read [Observability](./observability) before putting the service under sustained load.
3. Keep [Runbook](./runbook) close to day-to-day operations.
4. Use [Release Gates](./release-gates) as the pre-ship checklist for code and documentation changes.
5. Use [Docs Style Guide](./docs-style-guide) when editing or expanding the documentation set.
