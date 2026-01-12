---
layout: default
title: Agent Components
---

# Agent component boundaries

This page describes module boundaries and dependencies to guide maintenance and extension.

## Module map

### 1) `protocol/` (stable UI ↔ Engine contract)

- `protocol/op.py`: ops (ConfigureSession / UserInput / Interrupt / Approval)
- `protocol/events.py`: event messages (AgentMessage / TaskComplete / Error)
- `protocol/types.py`: SessionConfig / Artifact / Bookmark
- `protocol/serde.py`: JSON framing + version compatibility

### 2) `engine/` (core engine)

- `engine/argis.py`: Session/Task/Turn loop
- `engine/session.py`: session state
- `engine/task.py`: task lifecycle
- `engine/turn.py`: turn execution + input handling
- `engine/orchestrator.py`: routing, tool execution, escalation, policy call
- `engine/router.py`: FAST/STANDARD/DEEP planning
- `engine/policy.py`: verdict entry (rules + fusion)
- `engine/explanation.py`: evidence-based explanations
- `engine/report.py`: Markdown report rendering
- `engine/recorder.py`: JSONL recording (audit)
- `engine/player.py`: JSONL replay (recompute verdicts)

### 3) `apps/` (entry points / UI)

- `apps/cli/main.py`: CLI commands `detect` / `replay`
- `apps/demo/gradio_app.py`: Gradio demo

### 4) `schemas/` (input/evidence/explanation contracts)

- `schemas/email_schema.py`: `EmailInput`, `AttachmentMeta`
- `schemas/evidence_schema.py`: `EvidenceStore` and tool result models
- `schemas/explanation_schema.py`: `Explanation` output model

### 5) `tools_builtin/` (deterministic evidence sources)

- `tools_builtin/parser.py`: parse raw email into `EmailInput`
- `tools_builtin/header_analyzer.py`: SPF/DKIM/DMARC extraction
- `tools_builtin/url_analyzer.py`: offline URL parsing + lexical risk
- `tools_builtin/domain_risk.py`: lookalike/homoglyph detection
- `tools_builtin/content_analyzer.py`: intent/urgency/entity extraction (rule-based)
- `tools_builtin/attachment_analyzer.py`: attachment metadata scanning
- `tools_builtin/tool_registry.py`: optional registry for future integrations

### 6) `providers/` (model adapter layer)

- `providers/model/base.py`: ModelProvider interface
- `providers/model/ollama.py`: Ollama implementation (pluggable)

### 7) `connectors/` (external system entry)

- `connectors/gmail/`: Gmail OAuth + API entry
- `connectors/imap/`: IMAP entry

### 8) `scoring/` (risk fusion + hard rules)

- `scoring/fusion.py`: weighted fusion into 0–100 score and breakdown
- `scoring/rules.py`: hard rules (force `phishing` on match)

## Dependency direction (important)

Keep dependencies one-way to avoid cycles:

- `tools_builtin/` and `scoring/` depend on `schemas/`.
- `engine/` depends on `protocol/`, `schemas/`, `tools_builtin/`, `scoring/`.
- `apps/` depends on `protocol/` (drives the engine via ops/events).
- `schemas/` depend on no higher layers.

## Extension points

- New evidence source: add a tool in `tools_builtin/`, extend `EvidenceStore`, and wire in orchestrator/registry.
- New scoring factor: update `scoring/fusion.py` and weights in `configs/profiles/balanced.yaml`.
- New hard rule: add a match in `scoring/rules.py` and tests.
