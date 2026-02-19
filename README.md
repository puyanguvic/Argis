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

## Skills (SkillsBench style)

Argis now uses the same lightweight convention as SkillsBench: each skill is a folder containing `SKILL.md` under local `skills/`.

List installable remote skills from SkillsBench:

```bash
python scripts/skillsbench_skills.py --list
```

Install specific skills into project `skills/`:

```bash
python scripts/skillsbench_skills.py --install threat-detection openai-vision image-ocr
```

By default runtime auto-discovers local skills from `skills/`. You can override path with:

```bash
export MY_AGENT_APP_SKILLS_DIR=/path/to/skills
```

API `/analyze` responses now include both `runtime.installed_skills` and top-level `skills` summary (`dir`, `count`, `names`, `installed`).

## Security policy switches

Safe defaults: URL fetch is disabled, private-network access is blocked, OCR/audio transcription are off.

```bash
# One switch: enable full deep analysis pipeline with built-in defaults
export MY_AGENT_APP_ENABLE_DEEP_ANALYSIS=true
```

If you need fine-grained control later, you can still override individual options (backend/model/limits) via env vars.

## Providers / Profiles

Default runtime is local Ollama (`profile=ollama`, `model=ollama/qwen2.5:7b`).
So without extra env vars, the app prefers local inference over OpenAI API.

OpenAI:

```bash
export MY_AGENT_APP_PROFILE=openai
export OPENAI_API_KEY=your_key
uv run python -m phish_email_detection_agent --text "review this email"
```

LiteLLM + Ollama (local):

```bash
ollama pull qwen2.5:7b
ollama pull llama3.1:8b
uv run python -m phish_email_detection_agent --text "review this email"
```

Temporary model override:

```bash
export MY_AGENT_APP_PROFILE=ollama
uv run python -m phish_email_detection_agent --model ollama/qwen2.5:3b --text "review this email"
```

## Layout

```text
src/phish_email_detection_agent/
  cli.py
  api/
  domain/
    email/
    url/
    attachment/
    evidence.py
  orchestrator/
  agents/
  providers/
  config/
  infra/
  tools/
    url_fetch/
    ocr/
    asr/
    intel/
    text/
    attachment/
  ui/
```
