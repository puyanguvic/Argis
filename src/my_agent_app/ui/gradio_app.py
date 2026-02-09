"""Gradio app entrypoint."""

from __future__ import annotations

import gradio as gr

from my_agent_app.app.run import run_once
from my_agent_app.ui.components import model_hint


def build() -> gr.Blocks:
    with gr.Blocks(title="my-agent-app") as demo:
        gr.Markdown("# my-agent-app")
        model_hint()
        inp = gr.Textbox(label="Input", lines=8)
        out = gr.Textbox(label="Result", lines=12)
        btn = gr.Button("Run")
        btn.click(run_once, inputs=inp, outputs=out)
    return demo


if __name__ == "__main__":
    build().launch()
