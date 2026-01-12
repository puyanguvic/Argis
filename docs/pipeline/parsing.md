---
layout: default
title: Parsing
---

# MIME / header / body parsing

This page describes raw email → `EmailInput` parsing logic and boundaries.

## Current implementation

Parser: `parse_raw_email(raw_email: str) -> EmailInput` (`tools_builtin/parser.py`)

Steps:

1. `email.message_from_string()` parses the message
2. Extract body:
   - `text/plain` → `body_text`
   - `text/html` → `body_html`
3. Collect headers:
   - join `msg.items()` into `raw_headers`
4. Read common fields:
   - `Subject`, `From`, `Reply-To`, `Date`
5. Extract URLs:
   - `extract_urls([body_text, body_html])` (`tools_builtin/url_utils.py`)

## Known limits

- Simplified charset/encoding handling (`decode(errors="ignore")`)
- No attachment parsing (`attachments=[]`)
- Complex MIME structures (inline/quoted-printable) may be incomplete

## Suggested enhancements

Maintain the `EmailInput` contract, but improve in the ingestion layer:

- robust charset and transfer-encoding handling
- HTML → readable text conversion and noise reduction
- attachment extraction and sha256 hashing
- structured header parsing (Authentication-Results, ARC, Received chains)
