# my-agent-app

A clean reference architecture for an agent application.

## Run

No-arg startup (recommended):

```bash
uv run python -m my_agent_app
```

Single input:

```bash
uv run python -m my_agent_app --text "Please verify your account now"
```

Defaults live in `configs/default.yaml`.
Switch profile by changing `profile: openai|litellm` in that file.
You can also one-line override via env: `MY_AGENT_APP_PROFILE=litellm`.

Use local/self-hosted models with LiteLLM (one-key switch):

```bash
export MY_AGENT_APP_PROFILE=litellm
uv run python -m my_agent_app --text "Please verify your account now"
```

## Layout

```text
my-agent-app/
├── pyproject.toml
├── uv.lock
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── src/my_agent_app/
├── examples/
├── tests/
├── scripts/
├── docs/
└── configs/
```
