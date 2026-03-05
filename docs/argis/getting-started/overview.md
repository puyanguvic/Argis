# Overview

Argis is a phishing email detection system with deterministic-first analysis and evidence-backed outputs.

## What Argis Optimizes For

- Deterministic and auditable behavior by default.
- Clear boundary between policy, tools, and orchestration.
- Bounded side effects in online runtime.
- Traceable evidence references in final results.

## Runtime Flow

1. Input parsing and normalization.
2. Evidence construction and precheck scoring.
3. Skill routing and optional deep analysis.
4. Optional judge pass and calibration.
5. Validation and final result emission.

## Continue Reading

- [Quickstart](./quickstart)
- [Concepts](./concepts)
- [Design](/design)
