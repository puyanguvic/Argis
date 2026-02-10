# Architecture

- `core/`: config, logging, errors.
- `tools/`: deterministic utilities and analyzers.
- `tools/plugins/`: auto-discovered `tool_*` plugin functions.
- `agents/contracts.py`: structured schemas for router/investigator/final output.
- `tools/preprocessing.py`: parse text/json/eml input, hidden-link extraction, attachment hashes.
- `tools/url_analysis.py`: sandbox-safe fetch policy + html phishing signal extraction.
- `tools/attachment_analysis.py`: file-type detection and deep static-safe attachment analysis.
- `tools/domain_intel.py`: domain heuristics (punycode, typosquat, risky tld).
- `agents/risk_fusion.py`: weighted risk fusion (`text/url/domain/attachment/ocr`).
- `agents/providers.py`: model factory (`openai` native; `local` via LiteLLM, local runtime with Ollama).
- `agents/tool_registry.py`: built-in + plugin + external tool registration.
- `agents/service.py`: multi-agent orchestration workflow.
- `app/`: assembly and runtime runners.
- `ui/`: Gradio demo.
- `src/phish_email_detection_agent/configs/default.yaml`: runtime defaults + provider profiles.

## Multi-agent flow

1. Router Agent picks depth path (`FAST | STANDARD | DEEP`).
2. Preprocessing extracts text/html URLs, hidden links, attachment metadata and hashes.
3. Deterministic precheck runs URL/domain/attachment analyzers and fusion scoring.
4. Investigator Agent performs deeper URL/attachment/content analysis when needed.
5. Summarizer Agent emits final verdict, risk score, indicators and actions.
6. If remote model is unavailable, deterministic fusion output is returned.

## Security defaults

- URL fetch disabled by default (`MY_AGENT_APP_ENABLE_URL_FETCH=false`).
- URL sandbox backend is configurable (`internal | firejail | docker`).
- Private network access denied (`MY_AGENT_APP_ALLOW_PRIVATE_NETWORK=false`).
- Redirect count, timeout and response-size are bounded.
- OCR/audio transcription disabled by default; explicit opt-in required.
