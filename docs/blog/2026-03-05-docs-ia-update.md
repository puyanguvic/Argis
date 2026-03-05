# 2026-03-05: Docs Information Architecture Update

## Summary

The documentation site navigation was redesigned into four top-level sections: `Home`, `API`, `Argis`, and `Blog`.

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
- Added `docs/blog/` for project blog posts.

## Impact

- New users can start from `Argis -> Getting Started`.
- Integrators can focus on `API` docs without scanning unrelated pages.
- Future updates can be announced and indexed via `Blog`.

## Follow-ups

1. Continue migrating long-form legacy pages into the new section layout.
2. Add release-driven blog posts and changelog cross-links.
