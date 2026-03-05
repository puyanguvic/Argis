# App

Use Argis as an HTTP inference service.

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

## Structured Request Example

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'content-type: application/json' \
  -d '{
    "text":"{\"subject\":\"Security Alert\",\"urls\":[\"https://example.com/reset\"],\"attachments\":[{\"name\":\"invoice.pdf\"}]}"
  }'
```

## Service-Side Notes

- API mode rejects `eml_path`.
- Use object-style attachments (`name`/`filename`).
- Keep `debug_evidence` off by default in production.

Read next:

- [API Guides and Concepts](/api/guides-concepts)
- [API Reference](/api/reference)
