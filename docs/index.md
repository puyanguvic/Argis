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

## Documentation Map

- Start with [Overview](/argis/getting-started/overview), [Quickstart](/argis/getting-started/quickstart), and [Explore](/argis/getting-started/explore) if you are new to the project.
- Use [Using Argis](/argis/using-argis/) for day-to-day operator and integration workflows.
- Use [Configurations](/argis/configurations/) to tune runtime profiles, policy controls, MCP usage, and skillpack behavior.
- Read [Architecture](/argis/architecture/) for the control-stack model and runtime flow.
- Read [Operations](/argis/operations/) for runbooks, observability, security boundaries, and release gates.
- Use [API](/api/) when integrating `POST /analyze` into services and pipelines.

## Canonical Structure

The documentation site now uses `/argis/` and `/api/` as the primary information architecture. The earlier root-level compatibility pages have been removed so the site has a single canonical structure.

## Current Focus

Recent documentation work has focused on:

- making the `/argis/` section the primary product documentation path
- separating product docs from API docs and blog content
- reducing duplicated entry points that previously made the site feel legacy-first

For release-level details, see the [v0.1.1 release page](https://github.com/puyanguvic/Argis/releases/tag/v0.1.1) and [CHANGELOG.md](https://github.com/puyanguvic/Argis/blob/main/CHANGELOG.md).
