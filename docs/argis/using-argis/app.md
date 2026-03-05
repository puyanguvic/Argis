---
title: App
description: Run Argis as an HTTP inference service with stable request validation, response structure, and runtime observability.
---

# App

Use Argis as an HTTP inference service.

## When To Use The App Surface

Run the app when callers should interact with Argis through a stable network contract instead of local process invocation. This is the right mode for:

- backend services
- queue consumers
- analyst tooling that calls a central inference service
- environments where request validation and evidence sanitization should happen at the boundary

## Start API Server

```bash
uv sync --extra api
PYTHONPATH=src uv run uvicorn phish_email_detection_agent.api.app:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints

- `GET /health`
- `POST /analyze`

## Minimal Request

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'content-type: application/json' \
  -d '{"text":"Please verify your account now"}'
```

This is the simplest production-safe shape because `text` remains an ordinary string.

## Structured Request Example

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'content-type: application/json' \
  -d '{
    "text":"{\"subject\":\"Security Alert\",\"urls\":[\"https://example.com/reset\"],\"attachments\":[{\"name\":\"invoice.pdf\"}]}"
  }'
```

Use this mode when upstream systems already extracted structured fields. It is more reproducible than forcing Argis to infer everything from free text.

## Service-Side Notes

- API mode rejects `eml_path`.
- Use object-style attachments (`name`/`filename`).
- Keep `debug_evidence` off by default in production.

## What The App Adds

Compared with CLI mode, the app surface adds:

- explicit request validation with `400` caller errors
- default evidence sanitization
- stricter rejection of path-like inputs
- stable JSON response structure for downstream systems

## Operational Recommendations

### Log the right fields

At minimum, capture:

- `verdict`
- `risk_score`
- `path`
- `provider_used`
- `fallback_reason`
- `runtime.profile`
- `runtime.model`

### Distinguish validation from degraded inference

- HTTP `400` means the caller sent an invalid request.
- HTTP `200` with `provider_used=*:*fallback` means the request was accepted and Argis returned deterministic degraded output.

### Keep debug evidence internal

`debug_evidence=true` is useful for controlled debugging, but it weakens the default protection the API provides around sensitive evidence detail.

Read next:

- [API Guides and Concepts](/api/guides-concepts)
- [API Reference](/api/reference)
