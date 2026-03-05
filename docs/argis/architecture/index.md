---
title: Architecture
description: Architectural overview of the Argis control stack, including layer responsibilities, runtime guarantees, and fallback behavior.
---

# Architecture

Argis architecture uses a layered, policy-centric control stack.

## What This Section Explains

This section explains why Argis is organized as a control stack instead of a monolithic “agent” abstraction, and how that choice shapes runtime behavior:

- deterministic evidence is built before remote judgment
- dependency direction is intentionally one-way
- side effects are capability-bounded rather than implicit
- fallback and validation are first-class parts of the runtime

## Reading Path

- Start with [Design Overview](./design-overview) for responsibilities, dependency direction, and design constraints.
- Continue to [Runtime Flow](./runtime-flow) for the actual online execution sequence and fallback behavior.
- Cross-reference [Operations](/argis/operations/) when you need runbook or observability guidance tied to the runtime.
