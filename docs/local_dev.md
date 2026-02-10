# Local Development

```bash
uv sync
PYTHONPATH=src uv run python -m phish_email_detection_agent
uv run pytest -q
```

Set env with `.env.example` values only when overriding `src/phish_email_detection_agent/configs/default.yaml`.
Recommended local model path:

```bash
ollama pull qwen2.5:1b
export MY_AGENT_APP_PROFILE=ollama
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "test message"
```
