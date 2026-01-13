---
layout: default
title: URL Analysis
redirect_from:
  - /skills/url-analysis.html
---

# URL, redirect, and obfuscation analysis

URLs are the most common phishing landing path. This skill checks presence and lexical risk signals that imply login/verification actions.

## Core signals

- URL presence (larger attack surface)
- Shorteners / jump hosts
- Suspicious TLDs (e.g., `.zip`, `.click`)
- IP-host URLs (bypass domain reputation)
- Login/verification keywords in URL path or host

## Current implementation

### URL extraction

- `extract_urls([body_text, body_html])` (`tools_builtin/url_utils.py`)
- Simplified regex: extracts `http(s)://...` and trims trailing punctuation

### URL parsing and lexical risk

- `url_chain_resolve(urls)` (`tools_builtin/url_analyzer.py`)
- Output: `UrlChainResult(chains=[UrlChainItem...])`
- Constraint: no network redirects; each URL yields a single-hop chain (`hops=[input]`)

### Scoring and rules

Fusion factors (`scoring/fusion.py`):

- `url_present`
- `url_login_keywords`
- `url_shortener`
- `url_ip_host`
- `url_suspicious_tld`

Hard rule example (`scoring/rules.py`):

- `dmarc_fail_reply_to_login_url`

## Reporting guidance

Reports should include:

- final URL / final domain (if available)
- triggered URL flags (shortener / suspicious_tld / login_keywords / ip_host)
- combined reasoning with auth failures or Reply-To mismatch if a hard rule triggered

## Optional extensions (sandboxed)

- Resolve redirect chains (HEAD/GET with max hops)
- Landing-page summary (title, form presence, brand markers, JS obfuscation)
- Download and MIME detection (sample only, no execution)

These should run in a sandbox and emit structured evidence fields.
