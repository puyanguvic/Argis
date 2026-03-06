---
title: Release Gates
description: Release checklist for Argis covering tests, documentation updates, API compatibility, and security boundary review.
---

# Release Gates

Checklist before publishing a release.

## Required Checks

1. `uv sync`
2. `ruff check src tests docs scripts`
3. `pytest -k 'not hf_phishing_email_balanced_sample'`

These checks are the minimum line of defense against shipping a broken runtime or stale docs.

## Required Documentation Updates

1. update `README.md`
2. update the canonical pages under `docs/argis/architecture/`
3. update the canonical pages under `docs/argis/operations/` or `docs/argis/using-argis/`
4. update `CHANGELOG.md`

If the API contract changed, the API pages under `docs/api/` should also be updated in the same change.
For wording, structure, and contributor expectations, follow [Docs Style Guide](./docs-style-guide).

## API Compatibility Gate

1. document request schema changes
2. preserve and document error codes
3. add migration notes for caller impact

This gate exists because external callers are more expensive to break than internal refactors are to perform.

## Security Gate

1. no unbounded side effects
2. API trust boundary remains strict
3. evidence exposure changes are explicit and documented

## Review Questions Before Release

- did this change alter request or response shape?
- did it change fallback behavior or runtime metadata?
- did it widen side-effect or trust-boundary assumptions?
- did it move a threshold or routing rule that operators depend on?

## Issue And Commit Hygiene

When work is tracked in GitHub issues:

1. reference the issue from the commit history or merge commit
2. verify the shipped change actually satisfies the issue scope
3. close the issue after the implementation is merged or shipped, with a pointer to the resolving commit or PR
