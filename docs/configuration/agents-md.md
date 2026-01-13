---
layout: default
title: AGENTS.md
---

# `AGENTS.md`

`AGENTS.md` files are local, human-authored instructions for contributors and automation.

This repo uses them to enforce safe handling of email content (treat headers/bodies as sensitive), prefer offline/deterministic tooling, and keep protocol boundaries stable (`protocol/`).

## Scoping rule (important)

An `AGENTS.md` applies to the directory tree rooted at its folder. Nested `AGENTS.md` files override parent scope rules.
