---
title: Ingestion
redirect_from:
  - /pipeline/ingestion.html
---

# Ingestion: EML / MSG / API

This page explains how email inputs become a normalized `EmailInput`.

## 1) Preferred entry: `EmailInput` JSON

The CLI reads `EmailInput` JSON by default:

```bash
phish-agent detect --input examples/email_sample.json
```

Implementation:

- `apps/cli/main.py`: read JSON and validate as `EmailInput`
- `schemas/email_schema.py`: input contract

Best for:

- service/API integrations (parsing and redaction done upstream)
- SIEM/gateway integrations (structured events)

## 2) Raw email text (.eml)

`AgentOrchestrator.detect_raw(raw_email)` parses raw email into `EmailInput`:

- Parser: `tools_builtin/parser.py` (Python `email` library)
- Gradio demo: `apps/demo/gradio_app.py` accepts raw email text

Note: the parser currently does not extract attachments; it only extracts body and headers.

## 3) MSG / platform APIs (current state)

`.msg` parsing and platform APIs are not implemented in this repo. Recommended in the integration layer:

- decode MSG → MIME/headers/body
- populate attachment metadata (filename/mime/size/sha256/flags)
- add organization context (allowlists, internal domains, contact relationships)

Always normalize to `EmailInput` before entering the pipeline.
