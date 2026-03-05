---
title: MCP
description: Guidance for using MCP resources and templates with Argis documentation, code work, and controlled context loading.
---

# MCP

MCP usage depends on connected MCP servers and runtime environment.

## What MCP Changes

MCP can widen the amount of retrievable context available to an operator or coding workflow. That is useful, but it also creates a new discipline problem: context can become noisy, implicit, or insufficiently bounded if operators fetch indiscriminately.

## Usage Guidelines

- load only necessary context/resources
- keep execution explicit and auditable
- avoid unbounded or implicit side effects
- keep fallback behavior deterministic where feasible

## Recommended Workflow

When using MCP in this repository:

1. discover resources or templates first
2. fetch only the minimum relevant entries
3. keep assumptions about external context explicit in the resulting work
4. avoid treating MCP as a replacement for repository-grounded evidence

This mirrors the broader Argis design: bounded context, explicit control flow, and traceable reasoning inputs.

## Documentation Workflow Suggestion

When using MCP for docs or code work:

1. discover resources/templates first
2. fetch only relevant entries
3. keep cross-source assumptions explicit

## Good Uses

- locating targeted documentation or structured metadata quickly
- reading narrow external context that informs a code or docs change
- inspecting server-provided resources without bulk-loading unrelated material

## Risky Uses

- pulling large amounts of loosely relevant context into one task
- letting external context implicitly override repository truth
- using MCP to create hidden runtime or product assumptions

Reference architecture constraints: [Design Overview](/argis/architecture/design-overview) and `AGENTS.md`.
