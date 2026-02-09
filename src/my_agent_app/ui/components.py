"""Reusable UI components."""

from __future__ import annotations

import gradio as gr


def model_hint() -> gr.Markdown:
    return gr.Markdown(
        "Provider/model come from env + configs/default.yaml. "
        "Use profile `ollama` for local OLLAMA via LiteLLM."
    )
