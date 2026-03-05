---
title: "2026-03-05: Docs Information Architecture Update"
description: Summary of the documentation site navigation redesign around canonical product, API, operations, architecture, and blog sections.
---

# 2026-03-05: Docs Information Architecture Update

## Summary

The documentation site navigation was redesigned around a single canonical structure, centered on `Docs`, `API`, `Architecture`, `Operations`, and `Blog`.

## Why This Change

- Reduce top navigation noise.
- Group content by reader intent rather than by historical file names.
- Separate product usage docs (`Argis`) from integration docs (`API`).

## What Changed

- Added `docs/argis/` with three grouped tracks:
  - Getting Started
  - Using Argis
  - Configurations
- Added `docs/api/` with:
  - Guides and Concepts
  - API Reference
  - API Contract
  - Migration Guide
- Added `docs/blog/` for project blog posts.
- Removed the old root-level compatibility pages so the site no longer presents two parallel doc structures.

## Impact

- New users can start from `Argis -> Getting Started`.
- Integrators can focus on `API` docs without scanning unrelated pages.
- Future updates can be announced and indexed via `Blog`.

## Follow-ups

1. Add release-driven blog posts for future product and API changes.
2. Continue expanding section landing pages so new readers can navigate by task, not by file name.
