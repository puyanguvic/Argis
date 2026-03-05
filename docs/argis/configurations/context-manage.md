# Context Manage

Context management in Argis should preserve determinism, traceability, and safety.

## Core Rules

- keep evidence references stable (`evidence_id` style where possible)
- preserve source/category metadata
- avoid opaque conclusions without indicators
- bound external fetch/analysis with explicit limits

## API Context Rules

- default API responses sanitize sensitive evidence
- `debug_evidence=true` is for trusted debugging only

## Practical Advice

Design downstream pipelines to store key indicators, runtime metadata, and fallback reasons for reproducible triage behavior.
