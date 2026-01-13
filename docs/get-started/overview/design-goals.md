---
title: Design Goals and Non-Goals
redirect_from:
  - /overview/design-goals.html
---

# Design goals and non-goals

## Goals

1. **Evidence-first**
   - All tool outputs flow into `EvidenceStore` (`schemas/evidence_schema.py`).
   - Scores and rules are fused from evidence with explainable breakdowns.

2. **Deterministic, offline by default**
   - Core flow runs without network access.
   - Easier to test, reproduce, and audit.

3. **Clear separation of responsibilities (Router / Tools / Policy)**
   - Router selects paths and plans (`engine/router.py`).
   - Tools turn raw inputs into structured evidence (`tools_builtin/`).
   - Policy fuses rules and scores into verdicts (`engine/policy.py`, `scoring/`).

4. **Audit and replay**
   - Each tool output can be recorded to JSONL (`engine/recorder.py`).
   - Replays recompute verdicts without re-running tools (`engine/player.py`).

5. **Actionable outputs**
   - Provide recommended actions: `allow / warn / quarantine` (`engine/explanation.py`, `engine/report.py`).
   - Reports serve both humans and machines (CLI JSON output).

## Non-goals

- **Perfect automatic judgment**: low-evidence, context-heavy emails should go to `suspicious` and escalation.
- **Online intel queries by default**: WHOIS/DNS/URL lookups, VT/URLScan are out of scope unless added as tools.
- **Dynamic execution or sandboxing**: attachments are not unpacked or executed.
- **Chain-of-thought**: explanations reference evidence and score breakdowns only.

## Success criteria

- Common phishing signals (lookalike domains, short links, suspicious TLDs, macro attachments) produce high scores and auditable evidence.
- Collaboration/OAuth abuse triggers context escalation to collect more evidence instead of arbitrary scoring.
- Rules and weights are tunable via `configs/profiles/balanced.yaml` and covered by tests (`tests/`).
