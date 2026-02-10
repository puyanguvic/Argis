"""Reusable UI components."""

from __future__ import annotations

import gradio as gr


def model_hint() -> gr.Markdown:
    return gr.Markdown(
        "Models come from env + configs/default.yaml. "
        "OpenAI uses native Agents SDK path; profile `ollama` uses LiteLLM + Ollama."
    )
