"""Gradio app entrypoint."""

from __future__ import annotations

import os

import gradio as gr

from my_agent_app.app.build_agent import create_agent
from my_agent_app.app.run import run_once
from my_agent_app.ui.components import model_hint


def _run_with_selected_model(text: str, model: str) -> str:
    selected = (model or "").strip() or None
    return run_once(text, model=selected)


def build() -> gr.Blocks:
    _, runtime = create_agent()
    current_model = str(runtime.get("model", ""))
    raw_choices = runtime.get("model_choices", [])
    choices = [str(item) for item in raw_choices if str(item).strip()]
    if current_model and current_model not in choices:
        choices.insert(0, current_model)

    with gr.Blocks(title="my-agent-app") as demo:
        gr.Markdown("# my-agent-app")
        model_hint()
        model = gr.Dropdown(
            choices=choices or [current_model],
            value=current_model if current_model else None,
            label="Model",
            allow_custom_value=True,
        )
        inp = gr.Textbox(label="Input", lines=8)
        out = gr.Textbox(label="Result", lines=12)
        btn = gr.Button("Run")
        btn.click(_run_with_selected_model, inputs=[inp, model], outputs=out)
    return demo


if __name__ == "__main__":
    share = os.getenv("MY_AGENT_APP_GRADIO_SHARE", "").strip().lower() in {"1", "true", "yes", "on"}
    build().launch(share=share)
