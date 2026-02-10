# phish-email-detection-agent

A professional phishing detection agent stack based on OpenAI Agents SDK.

## Core design (v2)

- Multi-agent workflow:
  - `Router Agent`: select `FAST | STANDARD | DEEP`
  - `Investigator Agent`: deep artifact analysis (text/URL/domain/attachment)
  - `Summarizer Agent`: final verdict + risk score + actions
- End-to-end attack-chain analysis:
  - email text + html parsing
  - URL safe fetch (sandbox policy + redirect chain + html signals)
  - attachment deep analyzer (PDF/image/audio/office/html static-safe pipeline)
  - domain intelligence (typosquat/punycode/risky-tld heuristics)
  - deterministic risk fusion (`text + url + domain + attachment + ocr`)
- Extensible tool architecture:
  - built-in tools
  - plugin auto-discovery from `src/phish_email_detection_agent/tools/plugins`
  - optional external modules via `MY_AGENT_APP_TOOL_MODULES`
- Model access strategy:
  - `openai`: native OpenAI Agents SDK model path
  - `local` (and non-OpenAI providers): unified through LiteLLM
  - local runtime: Ollama

## Run

```bash
uv run python -m phish_email_detection_agent
```

Install OCR/audio analysis dependencies (optional):

```bash
uv sync --extra analysis
```

Single input text:

```bash
uv run python -m phish_email_detection_agent --text "Please verify your account now"
```

Structured deep input (text + urls + attachments):

```bash
uv run python -m phish_email_detection_agent --text '{"text":"Urgent: login now","urls":["https://bit.ly/reset"],"attachments":["invoice.zip"]}'
```

EML input:

```bash
uv run python -m phish_email_detection_agent --text '{"eml_path":"/path/to/sample.eml"}'
```

## Security policy switches

Safe defaults: URL fetch is disabled, private-network access is blocked, OCR/audio transcription are off.

```bash
# One switch: enable full deep analysis pipeline with built-in defaults
export MY_AGENT_APP_ENABLE_DEEP_ANALYSIS=true
```

If you need fine-grained control later, you can still override individual options (backend/model/limits) via env vars.

## Providers / Profiles

OpenAI:

```bash
export MY_AGENT_APP_PROFILE=openai
export OPENAI_API_KEY=your_key
uv run python -m phish_email_detection_agent --text "review this email"
```

LiteLLM + Ollama (local):

```bash
ollama pull qwen2.5:1b
ollama pull qwen2.5:7b
ollama pull llama3.1:8b
export MY_AGENT_APP_PROFILE=ollama
uv run python -m phish_email_detection_agent --text "review this email"
```

Temporary model override:

```bash
export MY_AGENT_APP_PROFILE=ollama
uv run python -m phish_email_detection_agent --model ollama/qwen2.5:3b --text "review this email"
```

## Plugin tools

Auto-discovered plugin functions must be top-level and named `tool_*`.

- Built-in plugin directory: `src/phish_email_detection_agent/tools/plugins`
- External modules (comma-separated):

```bash
export MY_AGENT_APP_TOOL_MODULES="my_pkg.mail.tools,my_pkg.security.tools"
```

## Layout

```text
src/phish_email_detection_agent/
  agents/
  app/
  configs/
  core/
  tools/
    plugins/
  ui/
```
