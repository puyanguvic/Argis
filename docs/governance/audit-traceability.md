---
layout: default
title: Audit and Traceability
---

# Audit and traceability

Auditability is core to evidence-first systems: you must know not only *what* was decided, but *why* and what evidence was used.

## 1) Trace ID

`engine/orchestrator.py` builds a `trace_id` from `sender/subject/received_ts` (hashed) to correlate events and logs.

## 2) JSONL recording

`RunRecorder` (`engine/recorder.py`) records:

- `timestamp`
- `node_name` (router/tool/final)
- `input_state_hash`
- `tool_outputs` (tool outputs or decision summaries)

Note: `tool_outputs` may include URLs/domains; protect per privacy policy (see `policies/privacy.md`).

## 3) Replay and re-decision

`engine/player.py`:

- reads JSONL
- merges tool outputs into `EvidenceStore`
- recomputes verdict/score using current config

Use cases:

- reproduce issues without external dependencies
- compare changes across configs/rules/models

## 4) Production recommendations

- add `schema_version` and `config_version/config_hash` to event outputs
- maintain changelogs for rule/model updates
- apply access control, encryption, and retention policies to audit logs
