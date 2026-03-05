# Integrations

Argis supports multiple integration paths.

## HTTP API

- Use `POST /analyze` from web services, workers, and pipelines.
- Validate input schema before sending requests.

## Provider Profiles

- OpenAI profile via `MY_AGENT_APP_PROFILE=openai` and `OPENAI_API_KEY`.
- Local Ollama profile via `MY_AGENT_APP_PROFILE=ollama`.

## Skillpacks

- Local discovery from `skillpacks/`.
- Install/update via `scripts/skillsbench_skillpacks.py`.

## Observability Integration

- Capture `fallback_reason` and runtime metadata in logs/metrics.
- Track validation and fallback rates as reliability signals.
