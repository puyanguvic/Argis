"""Gradio demo app for the phishing email detection agent."""

from __future__ import annotations

import json

import gradio as gr

from engine.argis import ArgisEngine
from protocol.events import Error, TaskComplete
from protocol.op import UserInput


def _humanize_evidence(evidence: dict) -> str:
    lines: list[str] = []
    auth = evidence.get("header_auth")
    if auth:
        lines.append(
            "Header auth: spf={spf}, dkim={dkim}, dmarc={dmarc}, aligned={aligned}".format(
                spf=auth.get("spf"),
                dkim=auth.get("dkim"),
                dmarc=auth.get("dmarc"),
                aligned=auth.get("aligned"),
            )
        )
        for anomaly in auth.get("anomalies", []):
            lines.append(f"- anomaly:{anomaly}")
    url_chain = evidence.get("url_chain") or {}
    if url_chain.get("chains"):
        lines.append("URLs:")
        for chain in url_chain.get("chains", []):
            lines.append(f"- {chain.get('final_url')} ({chain.get('final_domain')})")
    domain_risk = evidence.get("domain_risk") or {}
    if domain_risk.get("items"):
        lines.append("Domain risk:")
        for item in domain_risk.get("items", []):
            flags = item.get("risk_flags") or []
            if flags:
                lines.append(f"- {item.get('domain')}: {', '.join(flags)}")
    semantic = evidence.get("semantic")
    if semantic:
        urgency = semantic.get("urgency", semantic.get("urgency_level"))
        lines.append(
            f"Semantic: intent={semantic.get('intent')}, urgency={urgency}"
        )
    attachment_scan = evidence.get("attachment_scan") or {}
    if attachment_scan.get("items"):
        lines.append("Attachments:")
        for item in attachment_scan.get("items", []):
            lines.append(
                f"- {item.get('sha256')}: macro={item.get('has_macro')}, "
                f"exec={item.get('is_executable')}"
            )
    return "\n".join(lines) if lines else "No evidence extracted."


def _extract_task_artifacts(events) -> dict[str, dict]:
    artifacts: dict[str, dict] = {}
    for event in events:
        if isinstance(event, Error):
            raise RuntimeError(event.message)
        if isinstance(event, TaskComplete):
            for artifact in event.artifacts:
                artifacts[artifact.kind] = artifact.payload
    return artifacts


ENGINE = ArgisEngine()


def analyze_email(raw_email: str) -> tuple[str, str, str, str, str]:
    try:
        events = ENGINE.submit(
            UserInput(session_id="gradio", input_kind="raw_email", payload=raw_email)
        )
        artifacts = _extract_task_artifacts(events)
        payload = artifacts.get("detection_result") or {}
        report_md = artifacts.get("report_md", {}).get("text", "")
        summary = payload.get("summary") or "Unknown email"
        decision = f"{payload.get('verdict')} (score={payload.get('risk_score')})"
        evidence = payload.get("evidence") or {}
        evidence_human = _humanize_evidence(evidence)
        evidence_json = json.dumps(evidence, indent=2, ensure_ascii=True)
        return summary, decision, report_md, evidence_human, evidence_json
    except RuntimeError as exc:
        return "Error", f"error: {exc}", "", "", ""


def build_demo() -> gr.Blocks:
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
        report_md = gr.Markdown(label="Report")
        evidence_human = gr.Textbox(label="Evidence", lines=12)
        with gr.Accordion("Evidence (JSON)", open=False):
            evidence_json = gr.Textbox(lines=12)

        run_btn.click(
            analyze_email,
            inputs=raw_email,
            outputs=[summary, decision, report_md, evidence_human, evidence_json],
        )
    return demo


if __name__ == "__main__":
    build_demo().launch(share=True)
