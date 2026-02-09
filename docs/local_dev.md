# Local Development

```bash
uv sync
PYTHONPATH=src uv run python -m my_agent_app
./scripts/test.sh
```

Set env with `.env.example` values only when overriding `configs/default.yaml`.
Recommended override: `MY_AGENT_APP_PROFILE=litellm` for local/self-hosted model path.
