---
title: Agents.md
description: Repository-level engineering contract for architecture boundaries, migration discipline, runtime flow, and documentation quality in Argis.
---

# Agents.md

Repository-level agent instruction contract lives in `AGENTS.md`.

## It Defines

- architecture layers and dependency direction
- runtime flow contract
- evidence and traceability expectations
- migration and API-stability constraints
- quality gates and done criteria

## Why It Matters

`AGENTS.md` is not decorative repository metadata. It is the local engineering contract that keeps documentation changes, architecture changes, and runtime behavior aligned. In this project it plays the role of a concise system constitution:

- which layers may depend on which others
- what the runtime flow must continue to guarantee
- how migrations and compatibility work
- which quality gates define “done”

## When To Read It Carefully

Read `AGENTS.md` before making changes that touch:

- package boundaries or imports
- API or response-shape behavior
- policy versus tool responsibilities
- compatibility layers or migrations
- docs that describe system guarantees

## Practical Rule

If a proposed change conflicts with `AGENTS.md`, the change needs stronger justification than “the code still works.” The repository contract is there to prevent architectural drift and undocumented behavior changes.

When changing docs, code, or interfaces, align behavior with this contract and update related tests/docs together.
