---
title: Integration
redirect_from:
  - /deployment/integration.html
---

# Integration: SIEM / email gateway

This page describes integration patterns and recommended fields.

## 1) Typical integration flow

1. Gateway/platform captures email event (Message-ID, recipients, metadata).
2. Ingestion layer parses email and builds `EmailInput`.
3. Detection core returns JSON output.
4. Execute actions based on `recommended_action`:
   - `allow`: deliver
   - `warn`: notify user + review queue
   - `quarantine`: isolate/block
5. Write event to SIEM and correlate with tickets.

## 2) Suggested fields

Minimum set:

- `verdict`, `risk_score`, `recommended_action`, `top_signals`, `trace_id`, `profile`

Enhanced set (from ingestion layer):

- `message_id`, `thread_id`, `tenant_id`
- `sender`, `sender_domain`, `reply_to`, `recipient`
- `urls` (raw + normalized), `attachments` (sha256/mime/size)
- `delivery_action` (gateway action) and final disposition

## 3) Safety guidance

- Avoid clickable URLs in tickets/alerts (or disable by default).
- For `suspicious` and BEC intents, require stricter human approval workflows.
