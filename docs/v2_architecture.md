# Phish Email Detection Agent v2

## Goal

Build an end-to-end phishing detector that can reason over the full attack chain:

`email text/html -> embedded URL -> remote page -> downloaded/attached payload`.

## Pipeline (current)

1. Input normalization and EML/JSON parsing (`domain/email/parse.py`).
1. Header and URL/domain evidence extraction (`tools/intel/*`, `domain/url/*`).
1. Conditional deep context collection via safe URL fetch and attachment static/deep analysis (`tools/url_fetch/service.py`, `tools/attachment/analyze.py`).
1. Evidence pack assembly (`orchestrator/pipeline.py::_build_evidence_pack`).
1. Planner + executor + judge orchestration (`agents/pipeline/*`).
1. Fallback or merged final verdict (`agents/pipeline/router.py`).

## Security-first execution model

- URL fetch is opt-in only (`MY_AGENT_APP_ENABLE_URL_FETCH=false` by default).
- URL fetch supports sandbox backends: `internal`, `firejail`, `docker`.
- No private-network traversal unless explicitly allowed.
- Timeout, redirect count, and body size are bounded.
- Executable-style binary downloads are blocked in safe fetch.
- OCR/audio transcription are disabled by default and require explicit enablement.

## Evidence output

`TriageResult` now returns:

- `indicators`: merged text/url/attachment/chain indicators
- `evidence`: deterministic reports for URLs/domains/attachments and component scores
- `precheck`: raw deterministic analyzer output for reproducible experiments

Judge input is redacted evidence pack to reduce prompt injection and sensitive data exposure.

## Architectural updates in this round

- Added explicit `PipelineRuntime` contract (`agents/pipeline/runtime.py`) to decouple stages from service internals.
- Extracted evidence assembly into dedicated stage module (`agents/pipeline/evidence_stage.py`).
- Judge invocation is now route-gated (`review/deep`) instead of always-on when remote model exists.
- Added configurable `allow`-route judge gating (`never|sampled|always`, deterministic sampling).
- Updated architecture docs to align with real module paths and runtime composition.

## Research extension points

- Replace heuristic domain analyzer with external WHOIS/passive-DNS feeds.
- Replace static image/audio modules with OCR + Whisper production pipelines.
- Learn fusion weights from labeled attack-chain data (baseline is rule/weight-based).
- Add calibration layer for different environments (enterprise, SOC, ISP mail gateway).
