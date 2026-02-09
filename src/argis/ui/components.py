"""Optional reusable Gradio components."""

from __future__ import annotations

import gradio as gr


def model_selector(default: str = "ollama") -> gr.Dropdown:
    return gr.Dropdown(label="Model Provider", choices=["ollama"], value=default)
