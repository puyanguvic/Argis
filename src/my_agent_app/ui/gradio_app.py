"""Gradio app entrypoint."""

from __future__ import annotations

import json
import os
from typing import Any

import gradio as gr

from my_agent_app.app.build_agent import create_agent
from my_agent_app.ui.components import model_hint


def _format_stage_line(event: dict[str, Any]) -> str:
    stage = str(event.get("stage", "runtime")).upper()
    status = str(event.get("status", "info")).upper()
    message = str(event.get("message", ""))
    data = event.get("data")
    if isinstance(data, dict) and data:
        compact = ", ".join(f"{k}={json.dumps(v, ensure_ascii=True)}" for k, v in data.items())
        return f"[{stage}/{status}] {message} ({compact})"
    return f"[{stage}/{status}] {message}"


def _format_compact_result(final: dict[str, Any]) -> str:
    verdict = str(final.get("verdict", "")).lower()
    if verdict == "phishing":
        verdict_text = "Potential phishing"
    elif verdict == "benign":
        verdict_text = "No high-risk anomalies detected"
    else:
        verdict_text = "Result pending confirmation"

    reason = str(final.get("reason", "")).strip()
    indicators = final.get("indicators")
    indicator_text = ""
    if isinstance(indicators, list):
        cleaned = [str(item).strip() for item in indicators if str(item).strip()]
        if cleaned:
            indicator_text = f"Key indicators: {', '.join(cleaned[:3])}"
            if len(cleaned) > 3:
                indicator_text += " and others"

    summary_parts = [part for part in [reason, indicator_text] if part]
    summary = "; ".join(summary_parts) if summary_parts else "No explainable reason was returned."

    return f"Detection Result: {verdict_text}\nReason Summary: {summary}"


def _stream_with_selected_model(text: str, model: str):
    selected = (model or "").strip() or None
    agent, runtime = create_agent(model_override=selected)

    process_lines = [
        f"provider={runtime['provider']} model={runtime['model']} max_turns={runtime['max_turns']}",
    ]
    result_text = ""
    yield "\n".join(process_lines), result_text

    for event in agent.analyze_stream(text):
        if event.get("type") == "final":
            final = event.get("result")
            if isinstance(final, dict):
                result_text = _format_compact_result(final)
                process_lines.append("[DONE] Detection pipeline finished.")
                yield "\n".join(process_lines), result_text
            continue

        process_lines.append(_format_stage_line(event))
        yield "\n".join(process_lines), result_text


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
        process = gr.Textbox(label="Detection Process", lines=12)
        out = gr.Textbox(label="Result", lines=12)
        btn = gr.Button("Run")
        btn.click(_stream_with_selected_model, inputs=[inp, model], outputs=[process, out])
    return demo


if __name__ == "__main__":
    share = os.getenv("MY_AGENT_APP_GRADIO_SHARE", "").strip().lower() in {"1", "true", "yes", "on"}
    build().launch(share=share)
