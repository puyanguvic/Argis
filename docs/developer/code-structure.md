---
layout: default
title: Code Structure
---

# Code structure

Repository layout (aligned with `README.md`):

```
.
├── protocol/              # UI <-> Engine stable contract
├── engine/                # core engine (session/task/turn + pipeline)
├── tools_builtin/         # deterministic evidence sources
├── providers/             # model adapter layer
├── connectors/            # external system connectors
├── apps/                  # CLI/Gradio entry points
├── schemas/               # input/evidence/explanation schemas (Pydantic)
├── scoring/               # risk fusion and hard rules
├── configs/               # profiles / providers / connectors
├── examples/              # sample inputs
├── tests/                 # unit tests
└── docs/                  # documentation
```

Key entry points:

- CLI: `apps/cli/main.py` (`phish-agent`)
- Engine loop: `engine/argis.py`
- Orchestrator: `engine/orchestrator.py`
- Router: `engine/router.py`
- Policy: `engine/policy.py` + `scoring/`
