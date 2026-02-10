# Phish Email Detection Agent v2

## Goal

Build an end-to-end phishing detector that can reason over the full attack chain:

`email text/html -> embedded URL -> remote page -> downloaded/attached payload`.

## Pipeline

1. Input normalization (`tools/preprocessing.py`)
1. URL and domain analysis (`tools/url_analysis.py`, `tools/domain_intel.py`)
1. Attachment deep analysis (`tools/attachment_analysis.py`)
1. Multi-modal risk fusion (`agents/risk_fusion.py`)
1. Agent orchestration (`agents/service.py`)

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

## Research extension points

- Replace heuristic domain analyzer with external WHOIS/passive-DNS feeds.
- Replace static image/audio modules with OCR + Whisper production pipelines.
- Learn fusion weights from labeled attack-chain data (baseline is rule/weight-based).
- Add calibration layer for different environments (enterprise, SOC, ISP mail gateway).
