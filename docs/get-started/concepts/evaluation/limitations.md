---
layout: default
title: Known Limitations
redirect_from:
  - /evaluation/limitations.html
---

# Known limitations

This page summarizes key boundaries to set expectations.

## Coverage gaps

- Context-heavy BEC: lacks address book, thread history, finance workflow context
- High-quality APT: natural copy with weak technical signals; rule-based semantics are limited

## Evidence collection limits

- URL analysis does not follow redirects or analyze landing pages (offline default)
- Attachments are not unpacked or analyzed statically/dynamically
- Header parsing is simplified and may miss complex variants

## Risk management guidance

- Treat `suspicious` as the main path for “needs context/human review.”
- Add org-context evidence via connectors (allowlists, contacts, threads, finance systems).
- For online tools, enforce sandboxing and quota/timeout controls.

More granular failure modes are listed in `get-started/concepts/agent/failure-modes.md`.
