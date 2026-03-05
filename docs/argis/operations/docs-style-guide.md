---
title: Docs Style Guide
description: Editorial and structural standards for writing Argis documentation so pages stay implementation-backed, readable, and professionally consistent.
---

# Docs Style Guide

Use this page when adding or revising documentation in this repository. The goal is not only grammatical consistency, but documentation that remains technically trustworthy under change.

## Writing Principles

### Write to the current implementation

Documentation should describe current behavior, interfaces, constraints, and operator expectations. Avoid promising behavior that the code does not currently implement.

### Prefer explicitness over marketing language

Argis is a security-oriented system. Readers need clear statements about:

- what input is accepted
- what output is emitted
- what is deterministic
- what is optional
- what can fail and how failure is represented

### Separate public contract from implementation detail

It is acceptable to mention implementation-backed details, but pages should make clear which facts are:

- stable caller/operator contract
- operational guidance
- internal implementation detail that may evolve

## Tone

- write like an engineer explaining a production system
- avoid hype language and vague claims
- avoid hand-wavy words such as “smart”, “powerful”, or “seamless” unless they are backed by concrete explanation
- prefer short declarative sentences for boundary conditions and guarantees

## Page Structure

Most substantial pages should answer, in some order:

1. what this page is for
2. who should read it
3. what the key concepts or constraints are
4. what the operator or caller should do next

For technical reference pages, prefer this pattern:

- overview
- contract or behavior
- important edge cases
- related docs

For process or guide pages, prefer this pattern:

- when to use it
- how it works
- common mistakes
- next steps

## Terminology Rules

Use the canonical meanings from [Glossary](/argis/getting-started/glossary). In particular:

- `route` means the internal classification (`allow`, `review`, `deep`)
- `path` means the emitted runtime label (`FAST`, `STANDARD`, `DEEP`)
- `fallback` means degraded but valid output, not generic failure
- `API mode` and `CLI mode` should not be used interchangeably
- `EvidencePack` and `precheck` should be treated as distinct concepts

If a page introduces a term that is central across multiple sections, add it to the glossary.

## Examples And Code Blocks

- keep examples minimal but realistic
- prefer examples that reflect actual accepted input shapes
- show boundary-sensitive examples, not only happy paths
- avoid pseudocode when a short real command or JSON example would be clearer

For API examples, favor:

- a minimal valid request
- one structured request
- one example of runtime or fallback-related response interpretation

## Links And Cross-References

Pages should not end as dead ends. Add related docs or next-reading guidance when a reader is likely to need another page immediately after the current one.

Good cross-links:

- from API docs to security boundary and runbook
- from architecture docs to rules and operations
- from configuration docs to security boundary and release gates

## What To Update Together

When behavior changes, documentation updates should usually travel together:

- product behavior pages under `docs/argis/`
- API contract pages under `docs/api/`
- operational pages under `docs/argis/operations/`
- `README.md`
- `CHANGELOG.md`

## Review Checklist For Docs Changes

Before considering docs work complete, check:

- terminology is consistent with the glossary
- page purpose is obvious from the first screen
- examples match current implementation
- links point to canonical pages
- behavior changes include migration or operational guidance when needed
- the docs build still passes

## Related Docs

- [Glossary](/argis/getting-started/glossary)
- [Release Gates](./release-gates)
- [Agents.md](/argis/configurations/agents-md)
