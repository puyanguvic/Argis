# Architecture

## Goal

Build an end-to-end phishing detector that reasons over the full attack chain:

`email text/html -> embedded URL -> remote page -> downloaded/attached payload`.

## Pipeline (current)

1. Input normalization and EML/JSON parsing (`domain/email/parse.py`).
2. Header and URL/domain evidence extraction (`tools/intel/*`, `domain/url/*`).
3. Conditional deep context collection via safe URL fetch and attachment static/deep analysis (`tools/url_fetch/service.py`, `tools/attachment/analyze.py`).
4. Evidence pack assembly (`orchestrator/pipeline.py::_build_evidence_pack`).
5. Planner + executor + judge orchestration (`agents/pipeline/*`).
6. Fallback or merged final verdict (`agents/pipeline/router.py`).

Evidence construction uses a fixed whitelist-driven skill chain:

`EmailSurface -> HeaderAnalysis -> URLRisk -> NLPCues -> AttachmentSurface -> (optional) PageContentAnalysis -> (optional) AttachmentDeepAnalysis -> RiskFusion`

Each skill is capped at `<= 5` declared steps and emits execution trace in `precheck.skill_trace`.

## Security-first execution model

- URL fetch is opt-in only (`MY_AGENT_APP_ENABLE_URL_FETCH=false` by default).
- URL fetch supports sandbox backends: `internal`, `firejail`, `docker`.
- No private-network traversal unless explicitly allowed.
- Timeout, redirect count, and body size are bounded.
- Executable-style binary downloads are blocked in safe fetch.
- OCR/audio transcription are disabled by default and require explicit enablement.

## Evidence output

`TriageResult` returns:

- `indicators`: merged text/url/attachment/chain indicators
- `evidence`: deterministic reports for URLs/domains/attachments and component scores
- `precheck`: raw deterministic analyzer output for reproducible experiments

Judge input is a redacted evidence pack to reduce prompt injection and sensitive data exposure.

## Code layout

- `src/phish_email_detection_agent/domain/`: core data models and parsing (`email/`, `url/`, `attachment/`, `evidence.py`).
- `src/phish_email_detection_agent/tools/`: deterministic analyzers (header/domain/url fetch/attachment/text/OCR/ASR).
- `src/phish_email_detection_agent/agents/pipeline/`: stage-based orchestration (`evidence_stage`, `planner`, `executor`, `judge`, `router`, `policy`, `runtime`).
- `src/phish_email_detection_agent/orchestrator/pipeline.py`: composition root and evidence pack construction.
- `src/phish_email_detection_agent/providers/`: model provider adapters (OpenAI, Ollama/LiteLLM path).
- `src/phish_email_detection_agent/config/`: env+yaml config (`defaults.yaml`).
- `src/phish_email_detection_agent/api/`, `src/phish_email_detection_agent/ui/`, `src/phish_email_detection_agent/cli.py`: delivery interfaces.
