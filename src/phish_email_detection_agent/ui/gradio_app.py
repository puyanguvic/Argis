"""Gradio app entrypoint."""

from __future__ import annotations

import json
import os
from urllib.error import URLError
from urllib.parse import urljoin
from urllib.request import urlopen
from typing import Any

import gradio as gr

from phish_email_detection_agent.orchestrator.build import create_agent

PROVIDER_MODE_TO_PROFILE = {
    "api": "openai",
    "local": "ollama",
}

APP_CSS = """
:root {
  --bg: #f4f5f7;
  --surface: #ffffff;
  --text-main: #171a1f;
  --text-muted: #68707d;
  --border-soft: rgba(20, 25, 35, 0.1);
  --accent: #171a1f;
  --accent-soft: #262b33;
  --focus: rgba(23, 26, 31, 0.14);
}

.gradio-container {
  font-family: "IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif !important;
  color: var(--text-main);
  background: var(--bg);
}

.app-shell {
  max-width: 1080px;
  margin: 0 auto 24px auto;
  padding: 34px 10px 40px 10px;
  animation: rise-in 0.34s ease-out;
}

.hero {
  border: 1px solid var(--border-soft);
  border-radius: 8px;
  padding: 20px 22px;
  margin: 0 0 16px 0;
  background: var(--surface);
  box-shadow: none;
}

.hero h1 {
  margin: 0;
  line-height: 1.06;
  font-size: clamp(28px, 2.8vw, 36px);
  font-weight: 700;
  letter-spacing: -0.03em;
}

.hero p {
  margin: 8px 0 0 0;
  color: var(--text-muted);
  max-width: 68ch;
  font-size: 13px;
  line-height: 1.5;
}

.panel-card {
  border: 1px solid var(--border-soft);
  border-radius: 10px;
  background: var(--surface);
  box-shadow: none;
  padding: 8px;
}

.panel-title {
  margin: 0 0 11px 0;
  font-weight: 650;
  font-size: 12px;
  color: #434b58;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.top-grid,
.work-grid {
  gap: 14px !important;
}

.status-box {
  border-radius: 8px;
  border: 1px solid rgba(20, 25, 35, 0.1);
  background: #fbfcfd;
  padding: 10px 12px !important;
}

.status-box p {
  margin: 0 !important;
  color: #4d5562;
  font-size: 12px;
}

.gradio-container .gr-button.run-btn {
  border: 1px solid rgba(23, 26, 31, 0.08) !important;
  color: #fff !important;
  background: linear-gradient(145deg, var(--accent), var(--accent-soft)) !important;
  box-shadow: none;
  transition: transform 0.16s ease, filter 0.2s ease;
  font-weight: 620 !important;
}

.gradio-container .gr-button.run-btn:hover {
  transform: translateY(-1px);
  filter: brightness(1.05);
}

.gradio-container .gr-button.run-btn:focus-visible {
  outline: none;
  box-shadow: 0 0 0 3px var(--focus);
}

.gradio-container .gr-form,
.gradio-container .gr-box,
.gradio-container .gr-group {
  border-color: var(--border-soft) !important;
  background: var(--surface) !important;
}

.gradio-container textarea,
.gradio-container input {
  background: #fcfdfe !important;
}

.gradio-container textarea:focus,
.gradio-container input:focus,
.gradio-container .gr-input:focus-within,
.gradio-container .gr-textarea:focus-within {
  border-color: rgba(23, 26, 31, 0.36) !important;
  box-shadow: 0 0 0 3px var(--focus) !important;
}

.result-header {
  margin: 0 0 6px 0;
  color: #39414d;
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-weight: 650;
}

.footnote {
  margin-top: 6px !important;
  color: #868d98;
  font-size: 12px;
}

@keyframes rise-in {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

@media (max-width: 900px) {
  .hero {
    padding: 16px 16px;
  }
  .panel-card {
    border-radius: 9px;
  }
}
"""

HERO_HTML = """
<section class="hero">
  <h1>Email Threat Analyzer</h1>
  <p>
    Configure model execution, stream detection stages, and review final verdicts in one focused workspace.
  </p>
</section>
"""


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
    email_label = str(final.get("email_label", "")).strip().lower()
    if email_label == "phish_email":
        verdict_text = "Marked as phish email"
    elif email_label == "spam":
        verdict_text = "Marked as spam"
    elif verdict == "phishing":
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
    skill_names = _extract_skill_names(runtime)
    skills_line = (
        f"Loaded Skills: {len(skill_names)} ({', '.join(skill_names[:5])})"
        if skill_names
        else "Loaded Skills: 0"
    )
    tags = final.get("threat_tags")
    tag_line = ""
    if isinstance(tags, list) and tags:
        tag_line = f"Threat Tags: {', '.join(str(item) for item in tags)}"
    label_line = f"Email Label: {email_label or 'unknown'}"
    lines = [f"Detection Result: {verdict_text}", label_line, f"Reason Summary: {summary}"]
    if tag_line:
        lines.append(tag_line)
    lines.append(execution)
    lines.append(skills_line)
    return "\n".join(lines)


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


def _extract_skill_names(runtime: dict[str, Any]) -> list[str]:
    raw = runtime.get("installed_skills", [])
    names: list[str] = []
    if not isinstance(raw, list):
        return names
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if name:
            names.append(name)
    return names


def _format_skills_hint(runtime: dict[str, Any]) -> str:
    names = _extract_skill_names(runtime)
    root = str(runtime.get("skills_dir", "")).strip()
    if not names:
        if root:
            return f"Loaded Skills: 0 (dir={root})"
        return "Loaded Skills: 0"
    preview = ", ".join(names[:6])
    if len(names) > 6:
        preview += f", ... (+{len(names) - 6} more)"
    if root:
        return f"Loaded Skills: {len(names)} (dir={root})\n{preview}"
    return f"Loaded Skills: {len(names)}\n{preview}"


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
        _format_skills_hint(runtime),
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

    with gr.Blocks(
        title="phish-email-detection-agent",
        theme=gr.themes.Soft(primary_hue="orange", secondary_hue="teal", neutral_hue="slate"),
        css=APP_CSS,
    ) as demo:
        with gr.Column(elem_classes=["app-shell"]):
            gr.HTML(HERO_HTML)
            with gr.Row(elem_classes=["top-grid"]):
                with gr.Column(scale=4, elem_classes=["panel-card"]):
                    gr.Markdown("Runtime", elem_classes=["panel-title"])
                    runtime_hint = gr.Markdown(_format_runtime_hint(runtime), elem_classes=["status-box"])
                    skills_hint = gr.Markdown(_format_skills_hint(runtime), elem_classes=["status-box"])
                    backend_status = gr.Markdown(_format_backend_status(runtime), elem_classes=["status-box"])
                with gr.Column(scale=3, elem_classes=["panel-card"]):
                    gr.Markdown("Execution Controls", elem_classes=["panel-title"])
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
            with gr.Row(elem_classes=["work-grid"]):
                with gr.Column(scale=5, elem_classes=["panel-card"]):
                    gr.Markdown("Input Message", elem_classes=["panel-title"])
                    inp = gr.Textbox(
                        label="Email Content",
                        lines=14,
                        placeholder="Paste headers + body, suspicious URLs, and other raw email content here...",
                    )
                    btn = gr.Button("Analyze Message", variant="primary", elem_classes=["run-btn"])
                with gr.Column(scale=6, elem_classes=["panel-card"]):
                    gr.Markdown("Live Analysis", elem_classes=["panel-title"])
                    process = gr.Textbox(label="Detection Process", lines=10, autoscroll=True)
                    gr.Markdown("Final Verdict", elem_classes=["result-header"])
                    out = gr.Textbox(label="Result", lines=6)
            gr.Markdown(
                "Config source: `src/phish_email_detection_agent/config/defaults.yaml` plus environment variables.",
                elem_classes=["footnote"],
            )
        provider_mode.change(
            _reload_provider_state,
            inputs=[provider_mode],
            outputs=[model, runtime_hint, skills_hint, backend_status],
        )
        btn.click(_stream_with_selected_model, inputs=[inp, provider_mode, model], outputs=[process, out])
    return demo


if __name__ == "__main__":
    share = os.getenv("MY_AGENT_APP_GRADIO_SHARE", "true").strip().lower() in {"1", "true", "yes", "on"}
    build().launch(share=share)
