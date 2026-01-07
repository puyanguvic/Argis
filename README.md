---
title: Phish Email Detection Agent
emoji: "" 
colorFrom: "indigo"
colorTo: "teal"
sdk: gradio
app_file: apps/gradio_demo/app.py
pinned: false
---

# Phish Email Detection Agent

A modular, agent-style pipeline for analyzing emails and estimating phishing risk using layered tools, a lightweight classifier, and configurable policy logic.

## Hugging Face Spaces

This repo is ready to deploy to Hugging Face Spaces using Gradio. The Space will launch `apps/gradio_demo/app.py`.

## Project layout

```
phish-agent/
├── README.md
├── pyproject.toml
├── requirements.txt
├── .gitignore
├── .env.example
│
├── agent/
│   ├── __init__.py
│   ├── orchestrator.py      # Main Agent flow
│   ├── policy.py            # Risk fusion + decision policy
│   └── state.py             # Evidence + scores state
│
├── schemas/
│   ├── __init__.py
│   └── email_schema.py      # Unified Email schema (Pydantic)
│
├── tools/
│   ├── __init__.py
│   ├── parser.py            # .eml / raw email parsing
│   ├── header_analyzer.py   # From/Reply-To/SPF/DKIM logic
│   ├── url_analyzer.py      # URL extraction + lexical features
│   ├── content_analyzer.py  # NLP / intent / phishing language
│   └── attachment_analyzer.py
│
├── models/
│   └── lightweight_classifier/
│       ├── __init__.py
│       ├── train.py
│       ├── infer.py
│       └── tokenizer/
│
├── configs/
│   └── default.yaml         # Agent config (thresholds, weights, LLM policy)
│
├── apps/
│   └── gradio_demo/
│       ├── app.py
│       └── README.md
│
├── tests/
│   ├── __init__.py
│   ├── test_parser.py
│   ├── test_policy.py
│   └── test_tools.py
│
├── data/
│   └── samples/
│       └── README.md        # Instructions only, no real emails
│
└── docs/
    ├── architecture.md
    ├── threat_model.md
    └── methodology.md
```

## Quick start

1) Create a virtual environment and install dependencies (defined in `pyproject.toml`).
2) Copy `.env.example` to `.env` and fill in required values if needed.
3) Run tests:

```
pytest
```

## Local setup (uv)

```
./setup.sh
python apps/gradio_demo/app.py
```

Use `./setup.sh --no-local-llm` to skip installing local model dependencies.

## Hugging Face Spaces

Spaces installs from `requirements.txt`. Keep it aligned with `pyproject.toml` core deps (not a lockfile snapshot) for deployment.

## Notes

- `agent/orchestrator.py` is the main entry point for the analysis pipeline.
- The pipeline is implemented with LangGraph for explicit, extensible flow control.
- Tools in `tools/` operate on a unified email schema defined in `schemas/email_schema.py`.
- `configs/default.yaml` controls thresholds, weights, and policy behavior.
- `apps/gradio_demo/` contains a simple UI for manual testing.
- Optional LLM scoring can be enabled via the `llm` section in `configs/default.yaml` with either `huggingface_api` or `huggingface_local`.
- For `huggingface_local`, install extra deps: `pip install .[local-llm]`.
  - The default config enables `huggingface_local` with `Qwen/Qwen2.5-1.5B-Instruct`.
  - First run will download model weights from Hugging Face and cache them locally.

## Clearing local model cache

Use the helper script to remove cached Hugging Face model weights:

```
python tools/clear_model_cache.py --model Qwen/Qwen2.5-1.5B-Instruct
```

To remove the entire Hugging Face hub cache:

```
python tools/clear_model_cache.py --all
```

## License

TBD
