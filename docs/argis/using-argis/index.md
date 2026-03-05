---
title: Using Argis
description: Choose between CLI, app, and integration workflows, and understand the trust-boundary and observability differences between them.
---

# Using Argis

This section covers the practical ways people interact with Argis once the project is installed.

## Choose The Right Surface

Argis exposes multiple delivery surfaces, but they are not interchangeable. The right one depends on who is calling the system and which trust boundary applies:

- use the CLI when the operator controls the machine and local files are acceptable input
- use the app/API when the caller is external or service-to-service
- use integration workflows when Argis is one stage inside a larger processing pipeline

## Choose a Workflow

- Use [CLI](./cli) for local triage, debugging, experiments, and direct operator workflows.
- Use [App](./app) when Argis needs to run as an HTTP inference service.
- Use [Integrations](./integrations) when embedding Argis into workers, queues, or larger systems.

## What Changes Between Workflows

- the entry point you run
- which input shapes are appropriate
- what trust boundary applies to local files and evidence detail
- which observability fields matter most in production

## Practical Differences

### CLI

Best when you want to:

- iterate on prompts or sample emails quickly
- inspect local EML files
- test provider or model overrides
- debug capability flags without exposing an HTTP surface

### App

Best when you want to:

- expose `POST /analyze` to internal services
- enforce a stable caller contract
- preserve API trust-boundary validation
- collect standardized runtime metadata and fallback telemetry

### Integrations

Best when you want to:

- normalize email data upstream
- use Argis as a triage stage in a queue or event-driven flow
- store indicators and runtime state alongside downstream case data

## Shared Output Expectations

Regardless of the surface, the core runtime is the same. You should expect:

- a bounded verdict and risk score
- evidence-backed indicators
- deterministic fallback when remote execution is unavailable or fails
- explicit runtime state rather than silent capability assumptions

## Related Docs

- [Quickstart](/argis/getting-started/quickstart)
- [Configurations](/argis/configurations/)
- [API](/api/)
- [Operations](/argis/operations/)

## Next Reading

- If you are starting locally, continue to [CLI](./cli).
- If you are exposing Argis as a service, continue to [App](./app).
- If Argis is only one step in a larger platform, continue to [Integrations](./integrations).
