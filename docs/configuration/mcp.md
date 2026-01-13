---
layout: default
title: MCP
---

# MCP

Argis does not currently include a Model Context Protocol (MCP) integration.

If MCP support is added, this page should describe:

- supported MCP servers and resources
- security model (redaction, allowlists)
- how MCP results flow into `EvidenceStore` without breaking explainability

## Guardrails (recommended)

- Treat all email content/headers as sensitive; redact before sending to any external server.
- Keep the stable boundary: MCP results should remain “evidence”, not implicit decisions.
