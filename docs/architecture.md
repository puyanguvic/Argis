# Architecture

## Design principles for phishing AI agent

1. Evidence-first: deterministic analyzers build a typed `EvidencePack` before any LLM call.
2. Least privilege: network/file-heavy capabilities are opt-in and policy-gated.
3. Fail-safe: if remote judge is unavailable or errors, deterministic fallback still returns a verdict.
4. Explainability: all final outputs carry indicators, evidence, and provenance timing/errors.
5. Composable pipeline: planner/executor/judge are isolated stages with explicit runtime contracts.

## Code layout

- `src/phish_email_detection_agent/domain/`: core data models and parsing (`email/`, `url/`, `attachment/`, `evidence.py`).
- `src/phish_email_detection_agent/tools/`: deterministic analyzers (header/domain/url fetch/attachment/text/OCR/ASR).
- `src/phish_email_detection_agent/agents/pipeline/`: stage-based orchestration primitives (`evidence_stage`, `planner`, `executor`, `judge`, `router`, `policy`, `runtime`).
- `src/phish_email_detection_agent/orchestrator/pipeline.py`: `AgentService` composition root and evidence pack construction.
- `src/phish_email_detection_agent/providers/`: model provider adapters (OpenAI, Ollama/LiteLLM path).
- `src/phish_email_detection_agent/config/`: env+yaml config system (`defaults.yaml`).
- `src/phish_email_detection_agent/api/`, `src/phish_email_detection_agent/ui/`, `src/phish_email_detection_agent/cli.py`: delivery interfaces.

## Execution flow

1. Parse input (`domain.email.parse.parse_input_payload`).
2. Build deterministic evidence (`agents.pipeline.evidence_stage.EvidenceStage` via orchestrator wiring).
3. Plan execution path (`agents.pipeline.planner.Planner`).
4. Conditionally run judge (`review/deep` routes only, remote-capability gated).
5. Merge/calibrate verdict (`agents.pipeline.router`) or fallback deterministically.
6. Emit trace events for each stage (`orchestrator.tracing`).

Judge gating for `allow` route is policy-driven (`never | sampled | always`) with deterministic sampling support.

## Security defaults

- URL fetch off by default: `MY_AGENT_APP_ENABLE_URL_FETCH=false`.
- Private network blocked by default: `MY_AGENT_APP_ALLOW_PRIVATE_NETWORK=false`.
- Safe fetch limits enabled: timeout, redirects, response size.
- OCR/audio transcription off by default; explicit opt-in.
- Judge receives redacted evidence (`evidence/redact.py`) instead of raw artifacts.
