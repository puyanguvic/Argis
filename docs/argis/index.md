---
title: Argis Documentation
description: Canonical product documentation for running, configuring, integrating, and operating Argis.
---

# Argis Documentation

This is the canonical product documentation for Argis. Use it when you need to run the system, understand the runtime model, tune behavior, or move from local usage into an integrated or production-facing deployment.

<p class="docs-lead">Read this section as the product-facing layer of the system. It explains how to get Argis running, how to choose the right surface for interaction, and how to configure behavior without losing the safety and traceability properties that define the runtime.</p>

## What This Section Covers

The product documentation is organized around four practical concerns:

- getting a working environment up quickly
- choosing the right interaction mode for local or service use
- configuring runtime and policy controls without weakening safety boundaries
- understanding how the control stack produces evidence-backed results

## Recommended Reading Order

1. Start with [Overview](./getting-started/overview) for the product model.
2. Move to [Quickstart](./getting-started/quickstart) to get a local instance running.
3. Use [Explore](./getting-started/explore) to navigate by intent.
4. Read [Architecture](./architecture/) and [Operations](./operations/) once you need production or design detail.

## Mental Model

Argis is not a single prompt wrapped in an API. The runtime composes:

- input normalization for text, JSON payloads, and EML-derived content
- deterministic evidence construction and heuristic pre-scoring
- policy-driven route selection
- optional remote judge evaluation
- validation and final emission with runtime metadata

That design matters because it changes how you should operate the system:

- if you want predictable baseline behavior, use the deterministic path
- if you want richer artifact analysis, explicitly enable deep-analysis capabilities
- if you want model-assisted judgment, configure a provider and understand fallback behavior
- if you are exposing the API to untrusted callers, rely on the stricter API boundary rather than CLI assumptions

## By Intent

<div class="docs-grid">
  <a class="docs-card" href="./getting-started/overview">
    <div class="docs-card-title">I am new to Argis</div>
    <p class="docs-card-text">Start with the product model, first-run path, core concepts, and glossary.</p>
  </a>
  <a class="docs-card" href="./using-argis/">
    <div class="docs-card-title">I want to use Argis</div>
    <p class="docs-card-text">Choose between CLI, app, and integration workflows based on boundary and deployment needs.</p>
  </a>
  <a class="docs-card" href="./configurations/">
    <div class="docs-card-title">I want to configure behavior</div>
    <p class="docs-card-text">Work from profiles, capability flags, policy thresholds, and runtime extension points.</p>
  </a>
  <a class="docs-card" href="./architecture/">
    <div class="docs-card-title">I want system-level detail</div>
    <p class="docs-card-text">Review the control stack, route selection, evidence path, validation, and operational guarantees.</p>
  </a>
</div>

## Section Map

- [Getting Started](./getting-started/overview): orientation, quickstart, and navigation paths.
- [Using Argis](./using-argis/): local usage, service mode, and integration patterns.
- [Configurations](./configurations/): runtime controls, policy surfaces, and context management.
- [Architecture](./architecture/): design model, dependency rules, and execution flow.
- [Operations](./operations/): runbooks, observability, trust boundaries, and release discipline.

## Reader Paths

### Local evaluation and experimentation

Start with [Quickstart](./getting-started/quickstart), then continue to [CLI](./using-argis/cli) and [Config File](./configurations/config-file).

### Service integration

Start with [App](./using-argis/app), then move to the dedicated [API docs](/api/) and [Operations](./operations/) pages.

### Architecture review or technical due diligence

Start with [Concepts](./getting-started/concepts), then read [Design Overview](./architecture/design-overview) and [Runtime Flow](./architecture/runtime-flow).

<div class="signal-grid">
  <div class="signal-card">
    <span class="signal-value">3</span>
    <span class="signal-label">primary execution surfaces: CLI, API app, integrations</span>
  </div>
  <div class="signal-card">
    <span class="signal-value">5</span>
    <span class="signal-label">core product doc tracks: getting started, usage, config, architecture, operations</span>
  </div>
  <div class="signal-card">
    <span class="signal-value">1</span>
    <span class="signal-label">canonical product documentation tree under <code>/argis/</code></span>
  </div>
</div>

## Documentation Standards

This site is intended to describe current implementation and operational behavior. When pages change, they should stay consistent with:

- the runtime and API contract
- the architecture boundaries in `AGENTS.md`
- the release and documentation expectations in [Operations](/argis/operations/)
