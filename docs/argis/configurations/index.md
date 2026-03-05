---
title: Configurations
description: Runtime configuration model for profiles, deep-analysis capabilities, policy thresholds, MCP usage, and skillpack behavior in Argis.
---

# Configurations

This section documents the main control surfaces that shape Argis runtime behavior.

<p class="docs-lead">Think of configuration in Argis as runtime control, not as a bag of convenience toggles. Some settings pick the provider and model baseline. Others enable or bound side effects. Others move thresholds that change routing, judge eligibility, and final output behavior.</p>

## Configuration Layers

Argis configuration is easier to manage if you think in layers instead of in one long environment-variable list:

- profile and provider selection
- deep-analysis capability flags
- fetch and sandbox bounds
- scoring and judge policy thresholds
- local skillpack and MCP context behavior

Those layers affect different things. Some control which provider is used. Others control whether side-effectful capabilities are allowed at all. Others shape how deterministic evidence is scored and whether the judge is eligible to run.

## What You Can Configure

<div class="docs-grid">
  <a class="docs-card" href="./config-file">
    <div class="docs-card-title">Config File</div>
    <p class="docs-card-text">Profile resolution, env overrides, capability flags, fetch bounds, and policy thresholds.</p>
  </a>
  <a class="docs-card" href="./rules">
    <div class="docs-card-title">Rules</div>
    <p class="docs-card-text">Where routing, scoring, validation, boundary, and fallback rules live in the codebase.</p>
  </a>
  <a class="docs-card" href="./agents-md">
    <div class="docs-card-title">Agents.md</div>
    <p class="docs-card-text">Repository-level engineering contract for architecture boundaries and migration discipline.</p>
  </a>
  <a class="docs-card" href="./mcp">
    <div class="docs-card-title">MCP</div>
    <p class="docs-card-text">Controlled context-loading guidance when MCP servers are available.</p>
  </a>
  <a class="docs-card" href="./skills">
    <div class="docs-card-title">Skills</div>
    <p class="docs-card-text">Skillpack structure, installation flow, runtime discovery, and operational guidance.</p>
  </a>
  <a class="docs-card" href="./context-management">
    <div class="docs-card-title">Context Management</div>
    <p class="docs-card-text">Evidence retention, sanitized output, and reproducible downstream triage context.</p>
  </a>
</div>

## Configuration Principles

- keep policy decisions explicit
- keep side effects opt-in and bounded
- keep evidence references reproducible
- keep trust boundaries visible in API-facing behavior

## Operator Guidance

### Start from a profile

Use `MY_AGENT_APP_PROFILE` to select a coherent base runtime such as `ollama` or `openai`, then override only the settings that are truly environment-specific.

### Turn on deep analysis intentionally

`enable_deep_analysis` is a convenience switch, not a license to remove bounds. URL fetch, OCR, and audio transcription remain separate capabilities and should stay within explicit operational limits.

### Treat threshold tuning as policy work

Changing scoring and judge thresholds affects routing and final behavior. Those changes should be documented and reviewed like policy changes, not treated as casual environment tweaks.

## Related Docs

- [Architecture](/argis/architecture/)
- [Security Boundary](/argis/operations/security-boundary)
- [Release Gates](/argis/operations/release-gates)
