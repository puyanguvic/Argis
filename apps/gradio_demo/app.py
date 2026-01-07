"""Gradio demo app for the phishing email detection agent."""

from __future__ import annotations

import json
from pathlib import Path

import gradio as gr
import yaml

from agent.orchestrator import AgentOrchestrator
from tools.clear_model_cache import clear_cache, get_hf_cache_dir


def _humanize_evidence(evidence: dict) -> str:
    lines: list[str] = []

    def _section(title: str, data: dict) -> None:
        score = data.get("score")
        score_text = f"score={score:.2f}" if isinstance(score, (int, float)) else "score=unknown"
        lines.append(f"{title}: {score_text}")
        findings = data.get("findings") or []
        for finding in findings:
            lines.append(f"- {finding}")

    header_findings = {
        "missing_sender": "Missing sender address in headers.",
        "missing_subject": "Missing subject line.",
        "reply_to_mismatch": "Reply-To differs from From.",
    }
    url_findings = {
        "obfuscated_url": "Link is obfuscated (e.g., [.] or hxxp).",
        "brand_lookalike": "Domain looks like a brand with letter/number swaps.",
        "suspicious_domain_keyword": "Domain contains phishing-prone keywords (login/verify/secure).",
        "excessive_hyphens": "Domain has many hyphens.",
        "ip_address_url": "Link uses a raw IP address.",
        "punycode_domain": "Punycode domain (possible homograph).",
        "suspicious_at_symbol": "URL contains @ which can hide the real destination.",
    }
    attachment_findings = {"ext": "Suspicious attachment extension."}

    headers = evidence.get("headers", {})
    if headers:
        data = dict(headers)
        data["findings"] = [header_findings.get(item, item) for item in headers.get("findings", [])]
        _section("Headers", data)

    urls = evidence.get("urls", {})
    if urls:
        data = dict(urls)
        url_lines = []
        for item in urls.get("findings", []):
            url_lines.append(url_findings.get(item, item))
        data["findings"] = url_lines
        _section("Links", data)
        url_list = urls.get("urls") or []
        if url_list:
            lines.append("URLs:")
            for url in url_list:
                lines.append(f"- {url}")

    content = evidence.get("content", {})
    if content:
        content_findings = []
        for item in content.get("findings", []):
            if isinstance(item, str) and item.startswith("phrase:"):
                content_findings.append(f'Phrase found: "{item.split(":", 1)[1]}".')
            elif isinstance(item, str) and item.startswith("time_pressure:"):
                content_findings.append(f'Time pressure: "{item.split(":", 1)[1]}".')
            else:
                content_findings.append(item)
        data = dict(content)
        data["findings"] = content_findings
        _section("Content", data)
        llm = content.get("llm")
        if isinstance(llm, dict):
            llm_score = llm.get("score")
            if isinstance(llm_score, (int, float)):
                lines.append(f"LLM signal: score={llm_score:.2f}")
            reasons = llm.get("reasons") or []
            if reasons:
                lines.append("LLM reasons:")
                for reason in reasons:
                    lines.append(f"- {reason}")

    attachments = evidence.get("attachments", {})
    if attachments:
        data = dict(attachments)
        attachment_lines = []
        for item in attachments.get("findings", []):
            if isinstance(item, str) and item.startswith("ext:"):
                attachment_lines.append(
                    f'{attachment_findings["ext"]} Found "{item.split(":", 1)[1]}".'
                )
            else:
                attachment_lines.append(item)
        data["findings"] = attachment_lines
        _section("Attachments", data)

    final = evidence.get("final", {})
    if isinstance(final, dict) and final:
        risk = final.get("risk")
        label = final.get("label")
        if isinstance(risk, (int, float)):
            lines.append(f"Final decision: {label} (risk={risk:.2f})")
        elif label:
            lines.append(f"Final decision: {label}")
        final_reasons = final.get("evidence") or []
        if final_reasons:
            lines.append("Final rationale:")
            for reason in final_reasons:
                lines.append(f"- {reason}")

    tao_steps = evidence.get("tao", [])
    if isinstance(tao_steps, list) and tao_steps:
        lines.append("TAO steps:")
        for step in tao_steps:
            if isinstance(step, dict):
                action = step.get("action", "unknown")
                reason = step.get("reason", "")
                if reason:
                    lines.append(f"- {action}: {reason}")
                else:
                    lines.append(f"- {action}")

    return "\n".join(lines) if lines else "No evidence extracted."


def analyze_email(raw_email: str) -> tuple[str, str, str, str]:
    orchestrator = AgentOrchestrator()
    state = orchestrator.run(raw_email)

    summary = state.email.summary()
    decision = f"{state.label} (risk={state.risk:.2f})"
    evidence_human = _humanize_evidence(state.evidence)
    evidence_json = json.dumps(state.evidence, indent=2, ensure_ascii=True)
    return summary, decision, evidence_human, evidence_json


def build_demo() -> gr.Blocks:
    def _default_model_id() -> str:
        try:
            data = yaml.safe_load(Path("configs/default.yaml").read_text()) or {}
        except FileNotFoundError:
            return "Qwen/Qwen2.5-1.5B-Instruct"
        llm = data.get("llm", {})
        model = llm.get("model")
        return str(model) if model else "Qwen/Qwen2.5-1.5B-Instruct"

    with gr.Blocks(title="Phish Email Detection Agent") as demo:
        gr.Markdown("# Phish Email Detection Agent")
        gr.Markdown("Paste a raw email (.eml) below to analyze phishing risk.")

        raw_email = gr.Textbox(
            label="Raw Email",
            lines=12,
            placeholder="Paste .eml or raw email content here",
        )
        run_btn = gr.Button("Analyze")

        summary = gr.Textbox(label="Summary")
        decision = gr.Textbox(label="Decision")
        evidence_human = gr.Textbox(label="Evidence", lines=12)
        with gr.Accordion("Evidence (JSON)", open=False):
            evidence_json = gr.Textbox(lines=12)

        run_btn.click(
            analyze_email,
            inputs=raw_email,
            outputs=[summary, decision, evidence_human, evidence_json],
        )

        gr.Markdown("## Local model cache")
        cache_dir = gr.Textbox(
            label="Cache directory",
            value=str(get_hf_cache_dir()),
            interactive=False,
        )
        gr.Markdown("Clear cached Hugging Face model weights from this machine.")

        cache_scope = gr.Radio(
            choices=["Model only", "All cache"],
            value="Model only",
            label="Cache scope",
        )
        confirm_clear = gr.Checkbox(
            label="I understand this will delete cached model files.",
            value=False,
        )
        model_id = gr.Textbox(
            label="Model id",
            value=_default_model_id(),
            placeholder="e.g. Qwen/Qwen2.5-1.5B-Instruct",
        )
        clear_btn = gr.Button("Clear cache")
        cache_status = gr.Textbox(label="Cache status")

        def clear_cache_ui(scope: str, confirm: bool, model: str) -> tuple[str, str, bool]:
            if not confirm:
                return "Please confirm before clearing cache.", str(get_hf_cache_dir()), False
            if scope == "All cache":
                removed = clear_cache(None, all_cache=True)
                if removed is None:
                    status = "Nothing to remove."
                else:
                    status = f"Removed cache at: {removed}"
                return status, str(get_hf_cache_dir()), False

            model = model.strip()
            if not model:
                return "Model id is required for Model only.", str(get_hf_cache_dir()), False
            removed = clear_cache(model, all_cache=False)
            if removed is None:
                status = f"No cache found for model: {model}"
            else:
                status = f"Removed cache at: {removed}"
            return status, str(get_hf_cache_dir()), False

        cache_scope.change(
            lambda scope: gr.update(visible=scope == "Model only"),
            inputs=cache_scope,
            outputs=model_id,
        )
        clear_btn.click(
            clear_cache_ui,
            inputs=[cache_scope, confirm_clear, model_id],
            outputs=[cache_status, cache_dir, confirm_clear],
        )

    return demo


demo = build_demo()

if __name__ == "__main__":
    demo.launch(share=True)
