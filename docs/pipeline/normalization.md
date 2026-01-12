---
layout: default
title: Normalization and Deobfuscation
---

# Normalization and deobfuscation

Normalization turns attacker formatting/encoding tricks into stable signals for reproducible tools.

## Current implementation (minimal)

Lightweight normalization currently happens in:

- URL extraction strips common trailing punctuation (`tools_builtin/url_utils.py`)
- Semantic extraction lowercases merged subject/body (`tools_builtin/content_analyzer.py`)
- Domain extraction uses `tldextract` (`tools_builtin/url_analyzer.py`)

## Recommended normalization checklist

### Text normalization

- HTML → plain text (strip script/style, keep readable content)
- Unicode normalization (NFKC) and zero-width character stripping
- Replace common obfuscations: `hxxp`, `[.]`, spaced domains, etc.

### URL normalization

- Decode URL encoding and HTML entities
- Normalize userinfo/port, optionally strip tracking params
- Normalize punycode (show readable form + keep raw)

### Domain normalization

- Lowercase
- Extract registrable domain (eTLD+1)
- Identify org allowlists and internal domains

Normalization should happen before evidence tools or as an explicit evidence source to avoid implicit decision changes.
