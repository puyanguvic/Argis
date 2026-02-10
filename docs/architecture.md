# Architecture

- `core/`: config, logging, errors.
- `tools/`: deterministic utilities and analyzers.
- `tools/plugins/`: auto-discovered `tool_*` plugin functions.
- `agents/contracts.py`: structured schemas for router/investigator/final output.
- `agents/providers.py`: model factory (`openai` native; `local` via LiteLLM, local runtime with Ollama).
- `agents/tool_registry.py`: built-in + plugin + external tool registration.
- `agents/service.py`: multi-agent orchestration workflow.
- `app/`: assembly and runtime runners.
- `ui/`: Gradio demo.
- `configs/default.yaml`: runtime defaults + provider profiles.

## Multi-agent flow

1. Router Agent picks depth path (`FAST | STANDARD | DEEP`).
2. Investigator Agent performs URL/attachment/content analysis when needed.
3. Summarizer Agent emits final verdict, risk score, indicators and actions.
4. If remote model is unavailable, system falls back to deterministic local heuristics.
