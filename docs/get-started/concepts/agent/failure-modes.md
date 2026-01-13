---
layout: default
title: Known Failure Modes
redirect_from:
  - /agent/failure-modes.html
---

# Known failure modes and risks

This page lists current boundaries and potential sources of false positives/negatives, with mitigations.

## 1) Header parsing limitations

- `tools_builtin/header_analyzer.py` uses simplified regex extraction for `spf|dkim|dmarc=(pass|fail|none)`:
  - may miss complex `Authentication-Results` variants
  - does not parse multi-hop Received chains, ARC, or alignment details
- Mitigation: integrate a full-featured header parser and map outputs into `HeaderAuthResult`.

## 2) URL analysis does not follow redirects

- `tools_builtin/url_analyzer.py` is offline-only:
  - cannot observe multi-hop redirects, shortener landing pages, or downloads
- Mitigation: add an optional online tool (sandbox-controlled) that outputs redirect chains and landing summaries as evidence.

## 3) Limited domain similarity coverage

- `tools_builtin/domain_risk.py` uses a small static brand list (`_BRANDS`).
- Homoglyph detection is heuristic and limited for Unicode.
- Mitigation: expand brand catalogs/allowlists, add punycode decoding, and stronger homoglyph libraries.

## 4) Rule-based semantic extraction

- `tools_builtin/content_analyzer.py` uses keyword heuristics for intent/urgency:
  - may miss high-quality APT copy, cross-language, or industry jargon
  - may over-trigger on templated emails
- Mitigation: add a semantic model as **evidence**, while keeping policy decisions deterministic.

## 5) Attachment analysis is metadata-only

- `tools_builtin/attachment_analyzer.py` checks only extensions/flags.
- Cannot detect double extensions, embedded scripts, archive chains, or macro content.
- Mitigation: add unpacking/static feature extraction in an isolated environment, still emitting structured evidence.

## 6) Missing organizational context in BEC

- BEC often relies on org relationships and historical threads.
- Current `EmailInput` lacks address books, past threads, and identity graphs.
- Mitigation: provide additional context via connectors (e.g., “new contact” or “first-time payment”) into `EvidenceStore`.
