---
title: System Overview
redirect_from:
  - /architecture/system-overview.html
---

# System overview

## One-sentence summary

An evidence-driven phishing detection agent: **route planning → tool-based evidence → rules and risk fusion → structured explanation and report**.

Protocol definition: `../protocol/v1.md`.

## Core data models

- `EmailInput`: normalized input (`schemas/email_schema.py`)
- `EvidenceStore`: evidence bus (`schemas/evidence_schema.py`)
- `Explanation`: structured explanation (`schemas/explanation_schema.py`)
- `DetectionResult`: final result (`engine/state.py`)

## Core components

- **Protocol (stable contract)**: UI ↔ Engine ops/events (`protocol/`)
- **Engine**: Session/Task/Turn loop (`engine/argis.py`)
- **Router**: selects `FAST/STANDARD/DEEP` path and tool plan from quick features + header auth (`engine/router.py`)
- **Orchestrator**: executes tools, handles context escalation, invokes policy (`engine/orchestrator.py`)
- **Tools**: evidence sources turning raw inputs into structured signals (`tools_builtin/`)
- **Providers**: pluggable model/exec adapters (`providers/`)
- **Connectors**: external entry points (Gmail/IMAP/etc.) (`connectors/`)
- **Policy**: hard rules + risk fusion → verdict (`engine/policy.py`, `scoring/`)
- **Apps**: CLI / Gradio / API (`apps/`)
- **Reporting**: human report + machine JSON (`engine/report.py`, `apps/cli/main.py`)
- **Audit**: JSONL recording and replay (`engine/recorder.py`, `engine/player.py`)

## End-to-end data flow

```
EmailInput
  └─ Router: quick_features + header_auth_check
        └─ EvidenceStore(plan/path/preliminary_score)
              └─ Orchestrator: execute tools by plan
                    └─ EvidenceStore(tool outputs)
                          └─ Policy: hard_rules + risk_fusion
                                └─ (verdict, score, breakdown)
                                      └─ Explanation + Report/JSON
```

## Profiles (paths)

The system allocates an investigation budget based on cost/benefit:

- **FAST**: lightweight evidence for low-risk or low-signal cases (default: Header + Semantic)
- **STANDARD**: adds URL evidence (default: Header + Semantic + URL)
- **DEEP**: adds domain similarity and attachment checks (default: STANDARD + DomainRisk + AttachmentScan)

Profiles and tool sets are configured in `configs/profiles/balanced.yaml` (`engine/config.py`).

## Traceability and replay

- Each node/tool output can be recorded to JSONL (`--record run.jsonl`).
- `phish-agent replay --record run.jsonl` replays and recomputes verdicts without re-running tools.
