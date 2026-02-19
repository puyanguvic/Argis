# Testing Guide

## Test Layout

- `tests/api/`: API contract and response-shape tests.
- `tests/domain/`: email/url parsing and domain-model behavior.
- `tests/tools/`: deterministic tool catalog/intel behavior.
- `tests/policy/`: policy-layer registry/chain/import-boundary tests.
- `tests/orchestrator/`: pipeline control stack, scoring, routing, and fallback behavior.
- `tests/evaluation/`: dataset-backed offline evaluation tests (slower).

## Fast Local Cycle

```bash
ruff check src tests docs scripts
pytest -k 'not hf_phishing_email_balanced_sample'
```

## Targeted Suites

```bash
pytest tests/policy tests/orchestrator
pytest tests/api tests/domain tests/tools
```

## Full Evaluation

```bash
pytest tests/evaluation/test_hf_eval_balanced_sample.py
```

Use the evaluation test mainly for regression checkpoints, not every edit cycle.
