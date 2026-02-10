"""Gradio app entrypoint."""

from __future__ import annotations

import json
import os
from urllib.error import URLError
from urllib.parse import urljoin
from urllib.request import urlopen
from typing import Any

import gradio as gr

from phish_email_detection_agent.agents.build import create_agent

PROVIDER_MODE_TO_PROFILE = {
    "api": "openai",
    "local": "ollama",
}


def _is_local_provider(provider: Any) -> bool:
    return str(provider or "").strip().lower() in {"local", "ollama"}


def _format_stage_line(event: dict[str, Any]) -> str:
    stage = str(event.get("stage", "runtime")).upper()
    status = str(event.get("status", "info")).upper()
    message = str(event.get("message", ""))
    data = event.get("data")
    if isinstance(data, dict) and data:
        compact = ", ".join(f"{k}={json.dumps(v, ensure_ascii=True)}" for k, v in data.items())
        return f"[{stage}/{status}] {message} ({compact})"
    return f"[{stage}/{status}] {message}"


def _format_compact_result(final: dict[str, Any], runtime: dict[str, Any]) -> str:
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

    execution = (
        f"Model Used: profile={runtime.get('profile')} "
        f"provider={runtime.get('provider')} model={runtime.get('model')}"
    )
    return f"Detection Result: {verdict_text}\nReason Summary: {summary}\n{execution}"


def _resolve_model_options(runtime: dict[str, Any]) -> tuple[list[str], str | None]:
    current_model = str(runtime.get("model", "")).strip()
    raw_choices = runtime.get("model_choices", [])
    choices = [str(item).strip() for item in raw_choices if str(item).strip()]
    if current_model and current_model not in choices:
        choices.insert(0, current_model)
    return choices or ([current_model] if current_model else []), current_model or None


def _profile_from_provider_mode(mode: str) -> str:
    clean = str(mode or "").strip().lower()
    return PROVIDER_MODE_TO_PROFILE.get(clean, "openai")


def _provider_mode_from_profile(profile: str) -> str:
    clean = str(profile or "").strip().lower()
    if clean == "ollama":
        return "local"
    return "api"


def _check_ollama_status(api_base: str | None) -> str:
    base = str(api_base or "").strip()
    if not base:
        return "Backend Status: Ollama profile selected but `api_base` is empty."

    endpoint = urljoin(base if base.endswith("/") else f"{base}/", "api/tags")
    try:
        with urlopen(endpoint, timeout=1.5) as resp:
            if getattr(resp, "status", 0) != 200:
                return f"Backend Status: Ollama unreachable (HTTP {getattr(resp, 'status', 'unknown')})."
            payload = json.loads(resp.read().decode("utf-8"))
            models = payload.get("models", []) if isinstance(payload, dict) else []
            return f"Backend Status: Ollama reachable at {base} (models discovered: {len(models)})."
    except URLError as exc:
        return f"Backend Status: Ollama unreachable at {base} ({type(exc.reason).__name__})."
    except Exception as exc:  # pragma: no cover
        return f"Backend Status: Ollama check failed at {base} ({type(exc).__name__})."


def _normalize_ollama_model_name(model: str) -> str:
    clean = str(model or "").strip()
    if clean.startswith("ollama/"):
        return clean.split("/", 1)[1]
    return clean


def _fetch_ollama_model_names(api_base: str | None) -> tuple[set[str], str | None]:
    base = str(api_base or "").strip()
    if not base:
        return set(), "api_base is empty"

    endpoint = urljoin(base if base.endswith("/") else f"{base}/", "api/tags")
    try:
        with urlopen(endpoint, timeout=2.0) as resp:
            if getattr(resp, "status", 0) != 200:
                return set(), f"HTTP {getattr(resp, 'status', 'unknown')}"
            payload = json.loads(resp.read().decode("utf-8"))
    except URLError as exc:
        return set(), f"{type(exc.reason).__name__}"
    except Exception as exc:  # pragma: no cover
        return set(), type(exc).__name__

    models = payload.get("models", []) if isinstance(payload, dict) else []
    names: set[str] = set()
    for item in models:
        if not isinstance(item, dict):
            continue
        for key in ("name", "model"):
            raw = str(item.get(key, "")).strip()
            if not raw:
                continue
            names.add(raw)
            names.add(_normalize_ollama_model_name(raw))
    return names, None


def _fetch_ollama_models_for_dropdown(api_base: str | None) -> tuple[list[str], str | None]:
    names, error = _fetch_ollama_model_names(api_base)
    if error:
        return [], error
    normalized = sorted({item for item in names if "/" not in item})
    return [f"ollama/{item}" for item in normalized], None


def _format_backend_status(runtime: dict[str, Any]) -> str:
    if _is_local_provider(runtime.get("provider", "")):
        return _check_ollama_status(runtime.get("api_base"))
    return "Backend Status: OpenAI profile selected; local Ollama check skipped."


def _format_runtime_hint(runtime: dict[str, Any]) -> str:
    profile = str(runtime.get("profile", ""))
    provider = str(runtime.get("provider", ""))
    model = str(runtime.get("model", ""))
    hint = f"Current: profile={profile}, provider={provider}, model={model}"
    if _is_local_provider(provider):
        hint += " (for Ollama, ensure service is running at configured api_base)"
    return hint


def _reload_provider_state(provider_mode: str):
    selected_profile = _profile_from_provider_mode(provider_mode)
    _, runtime = create_agent(profile_override=selected_profile)
    choices, value = _resolve_model_options(runtime)
    if _is_local_provider(runtime.get("provider", "")):
        dynamic_choices, _ = _fetch_ollama_models_for_dropdown(runtime.get("api_base"))
        if dynamic_choices:
            choices = dynamic_choices
            if value not in choices:
                value = choices[0]
    return (
        gr.Dropdown(choices=choices, value=value, allow_custom_value=True),
        _format_runtime_hint(runtime),
        _format_backend_status(runtime),
    )


def _stream_with_selected_model(text: str, provider_mode: str, model: str):
    selected_profile = _profile_from_provider_mode(provider_mode)
    selected = (model or "").strip() or None
    agent, runtime = create_agent(profile_override=selected_profile, model_override=selected)

    process_lines = [
        (
            f"profile={runtime['profile']} provider={runtime['provider']} "
            f"model={runtime['model']} max_turns={runtime['max_turns']}"
        ),
    ]
    result_text = ""
    yield "\n".join(process_lines), result_text

    if _is_local_provider(runtime.get("provider", "")):
        available, error = _fetch_ollama_model_names(runtime.get("api_base"))
        requested = str(runtime.get("model", "")).strip()
        normalized = _normalize_ollama_model_name(requested)
        candidates = {requested, normalized, f"{normalized}:latest"}
        if error:
            process_lines.append("[BLOCKED] Pre-run model check failed.")
            result_text = (
                "Run blocked: unable to validate local Ollama models. "
                f"Reason: {error}. Check Ollama service and api_base."
            )
            yield "\n".join(process_lines), result_text
            return
        if not (candidates & available):
            installed = ", ".join(sorted(available)[:10]) if available else "(none)"
            process_lines.append("[BLOCKED] Selected model is not installed in local Ollama.")
            result_text = (
                "Run blocked: selected model is not available in local Ollama.\n"
                f"Selected: {requested}\n"
                f"Installed: {installed}"
            )
            yield "\n".join(process_lines), result_text
            return

    for event in agent.analyze_stream(text):
        if event.get("type") == "final":
            final = event.get("result")
            if isinstance(final, dict):
                result_text = _format_compact_result(final, runtime)
                process_lines.append("[DONE] Detection pipeline finished.")
                yield "\n".join(process_lines), result_text
            continue

        process_lines.append(_format_stage_line(event))
        yield "\n".join(process_lines), result_text


def build() -> gr.Blocks:
    _, runtime = create_agent()
    current_profile = str(runtime.get("profile", "openai")).strip() or "openai"
    current_provider_mode = _provider_mode_from_profile(current_profile)
    choices, current_model = _resolve_model_options(runtime)
    if _is_local_provider(runtime.get("provider", "")):
        dynamic_choices, _ = _fetch_ollama_models_for_dropdown(runtime.get("api_base"))
        if dynamic_choices:
            choices = dynamic_choices
            if current_model not in choices:
                current_model = choices[0]

    with gr.Blocks(title="phish-email-detection-agent") as demo:
        gr.Markdown("# phish-email-detection-agent")
        gr.Markdown(
            "Models come from env + `src/phish_email_detection_agent/config/defaults.yaml`. "
            "OpenAI uses native Agents SDK path; profile `ollama` uses LiteLLM + Ollama."
        )
        runtime_hint = gr.Markdown(_format_runtime_hint(runtime))
        backend_status = gr.Markdown(_format_backend_status(runtime))
        provider_mode = gr.Dropdown(
            choices=["api", "local"],
            value=current_provider_mode,
            label="Provider",
        )
        model = gr.Dropdown(
            choices=choices,
            value=current_model,
            label="Model",
            allow_custom_value=True,
        )
        inp = gr.Textbox(label="Input", lines=8)
        process = gr.Textbox(label="Detection Process", lines=12)
        out = gr.Textbox(label="Result", lines=12)
        btn = gr.Button("Run")
        provider_mode.change(
            _reload_provider_state,
            inputs=[provider_mode],
            outputs=[model, runtime_hint, backend_status],
        )
        btn.click(_stream_with_selected_model, inputs=[inp, provider_mode, model], outputs=[process, out])
    return demo


if __name__ == "__main__":
    share = os.getenv("MY_AGENT_APP_GRADIO_SHARE", "").strip().lower() in {"1", "true", "yes", "on"}
    build().launch(share=share)
