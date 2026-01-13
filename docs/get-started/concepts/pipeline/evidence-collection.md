---
layout: default
title: Evidence Collection
redirect_from:
  - /pipeline/evidence-collection.html
---

# Evidence collection

`EvidenceStore` is the evidence bus (`schemas/evidence_schema.py`). All tool outputs must be written into it; the decision layer uses evidence only.

## EvidenceStore field mapping

| Field | Produced by | Primary use |
| --- | --- | --- |
| `header_auth` | `header_auth_check` | auth failure/misalignment signals |
| `url_chain` | `url_chain_resolve` | URL flags and domain extraction |
| `domain_risk` | `domain_risk_assess` | lookalike/homoglyph/punycode |
| `semantic` | `semantic_extract` | intent/urgency/brands/actions |
| `attachment_scan` | `attachment_static_scan` | macro/executable extensions |
| `quick_features` | Router | routing and score inputs |
| `preliminary_score` | Router | FAST/STANDARD/DEEP selection |
| `plan` / `path` | Router | execution plan and profile |
| `hard_rule_matches` | Policy | matched hard-rule codes |
| `degradations` | Orchestrator | downgrade/upgrade/missing evidence flags |

## Tool execution and assignment

Tools run in `engine/orchestrator.py` and are assigned via `_assign_observation()`.

When extending, keep:

- tool outputs serializable (e.g., `.model_dump()` or JSON)
- `EvidenceStore` fields optional so profiles can collect partial evidence

## Audit: record & replay

- Record: `RunRecorder.record(node_name, input_state, tool_outputs)` writes JSONL (`engine/recorder.py`).
- Replay: `replay_run()` merges JSONL into `EvidenceStore` (`engine/player.py`).

This allows you to:

- reproduce verdicts without running external tools
- compare behavior across configs or rule versions
