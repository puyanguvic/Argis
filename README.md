# my-agent-app

A professional phishing detection agent stack based on OpenAI Agents SDK.

## Core design

- Multi-agent workflow:
  - `Router Agent`: select `FAST | STANDARD | DEEP`
  - `Investigator Agent`: deep artifact analysis (text/URL/attachment)
  - `Summarizer Agent`: final verdict + risk score + actions
- Extensible tool architecture:
  - built-in tools
  - plugin auto-discovery from `src/my_agent_app/tools/plugins`
  - optional external modules via `MY_AGENT_APP_TOOL_MODULES`
- Provider abstraction:
  - `openai` (OpenAI API)
  - `litellm` (including Ollama)

## Run

```bash
uv run python -m my_agent_app
```

Single input text:

```bash
uv run python -m my_agent_app --text "Please verify your account now"
```

Structured deep input (text + urls + attachments):

```bash
uv run python -m my_agent_app --text '{"text":"Urgent: login now","urls":["https://bit.ly/reset"],"attachments":["invoice.zip"]}'
```

## Providers

OpenAI:

```bash
export MY_AGENT_APP_PROFILE=openai
export OPENAI_API_KEY=your_key
uv run python -m my_agent_app --text "review this email"
```

LiteLLM + Ollama:

```bash
ollama pull qwen2.5:1b
export MY_AGENT_APP_PROFILE=ollama
uv run python -m my_agent_app --text "review this email"
```

Temporary model override:

```bash
export MY_AGENT_APP_PROFILE=ollama
uv run python -m my_agent_app --model ollama/qwen2.5:3b --text "review this email"
```

## Plugin tools

Auto-discovered plugin functions must be top-level and named `tool_*`.

- Built-in plugin directory: `src/my_agent_app/tools/plugins`
- External modules (comma-separated):

```bash
export MY_AGENT_APP_TOOL_MODULES="my_pkg.mail.tools,my_pkg.security.tools"
```

## Layout

```text
src/my_agent_app/
  agents/
  app/
  core/
  tools/
    plugins/
  ui/
```
