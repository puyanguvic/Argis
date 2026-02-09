"""Reusable UI components."""

from __future__ import annotations

import gradio as gr


def model_hint() -> gr.Markdown:
    return gr.Markdown("Using configured provider/model from env + configs/default.yaml")
