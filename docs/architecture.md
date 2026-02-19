# Architecture

## Goal

Build an end-to-end phishing detector that reasons over the full attack chain:

`email text/html -> embedded URL -> remote page -> downloaded/attached payload`.

## Pipeline (current)

1. Input normalization and EML/JSON parsing (`domain/email/parse.py`).
2. Header and URL/domain evidence extraction (`tools/intel/*`, `domain/url/*`).
3. Conditional deep context collection via safe URL fetch and attachment static/deep analysis (`tools/url_fetch/service.py`, `tools/attachment/analyze.py`).
4. Evidence pack assembly (`orchestrator/pipeline.py::_build_evidence_pack`).
5. Skill routing + executor + judge orchestration (`orchestrator/skill_router.py`, `orchestrator/stages/*`).
6. Fallback or merged final verdict (`orchestrator/verdict_routing.py`).

Evidence construction uses a fixed whitelist-driven skill chain:

`EmailSurface -> HeaderAnalysis -> URLRisk -> NLPCues -> AttachmentSurface -> (optional) PageContentAnalysis -> (optional) AttachmentDeepAnalysis -> RiskFusion`

Each skill is capped at `<= 5` declared steps and emits execution trace in `precheck.skill_trace`.

## Agent design paradigm

The agent follows a 3-layer design:

1. Decision / Policy Layer (`Skills`)
2. Execution Layer (`Tools`)
3. Environment (external world)

### 1) Decision / Policy Layer (`Skills`)

- Defines *when to do what* and *in which order*.
- Encodes orchestration policies such as skill sequencing, conditional branching, and stop/continue decisions.
- Owns high-level control flow (e.g., when to trigger optional deep page or attachment analysis).

In this project, this layer is primarily represented by:

- skill chain design in `orchestrator/pipeline.py`
- route decision in `orchestrator/skill_router.py`
- stage orchestration in `orchestrator/stages/*` (`executor`, `judge`, `runtime`)
- skill registry, fixed-chain definitions, and local skill discovery in `src/phish_email_detection_agent/skills/*`

### 2) Execution Layer (`Tools`)

- Defines *what can be done* through deterministic capabilities.
- Performs concrete actions such as parsing, URL/domain intel, safe fetch, and attachment analysis.
- Exposes bounded, auditable operations to the policy layer.

In this project, this layer is primarily represented by:

- `tools/intel/*`
- `tools/url_fetch/service.py`
- `tools/attachment/analyze.py`
- other deterministic analyzers under `src/phish_email_detection_agent/tools/`

### 3) Environment (external world)

This layer includes real-world inputs and systems the agent interacts with:

- incoming email content (text/html, headers, attachments)
- remote URLs/pages and network responses
- file artifacts and runtime/sandbox constraints

### Model responsibility

The model is responsible for task understanding and reasoning across layers:

- interprets task context and evidence
- applies policy/skill logic to decide next actions
- synthesizes outputs (including final verdict and rationale) from tool-produced evidence

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
- `src/phish_email_detection_agent/skills/`: skill registry, fixed skill-chain definitions, and local installed-skill catalog discovery.
- `src/phish_email_detection_agent/tools/`: deterministic analyzers plus tool registry/catalog.
- `src/phish_email_detection_agent/orchestrator/stages/`: stage primitives (`evidence_stage`, `evidence_builder`, `executor`, `judge`, `runtime`).
- `src/phish_email_detection_agent/orchestrator/pipeline.py`: composition root and service wiring.
- `src/phish_email_detection_agent/orchestrator/precheck.py`: deterministic precheck signal extraction and score fusion rules.
- `src/phish_email_detection_agent/orchestrator/skill_router.py`, `src/phish_email_detection_agent/orchestrator/pipeline_policy.py`, `src/phish_email_detection_agent/orchestrator/verdict_routing.py`, `src/phish_email_detection_agent/orchestrator/tool_executor.py`, `src/phish_email_detection_agent/orchestrator/evidence_store.py`, `src/phish_email_detection_agent/orchestrator/validator.py`, `src/phish_email_detection_agent/orchestrator/evaluator.py`: control-stack modules for routing, policy, verdict calibration, execution normalization, evidence identity, online guardrails, and offline evaluation.
- `src/phish_email_detection_agent/providers/`: model provider adapters (OpenAI, Ollama/LiteLLM path).
- `src/phish_email_detection_agent/config/`: env+yaml config (`defaults.yaml`).
- `src/phish_email_detection_agent/api/`, `src/phish_email_detection_agent/ui/`, `src/phish_email_detection_agent/cli.py`: delivery interfaces.
