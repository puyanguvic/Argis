"""Gradio demo app for the phishing email detection agent."""

from __future__ import annotations

import json

import gradio as gr

from agent.orchestrator import AgentOrchestrator
from agent.report import build_report


def _humanize_evidence(evidence) -> str:
    lines: list[str] = []
    if evidence.header_auth:
        auth = evidence.header_auth
        lines.append(
            f"Header auth: spf={auth.spf}, dkim={auth.dkim}, dmarc={auth.dmarc}, "
            f"aligned={auth.aligned}"
        )
        for anomaly in auth.anomalies:
            lines.append(f"- anomaly:{anomaly}")
    if evidence.url_chain and evidence.url_chain.chains:
        lines.append("URLs:")
        for chain in evidence.url_chain.chains:
            lines.append(f"- {chain.final_url} ({chain.final_domain})")
    if evidence.domain_risk and evidence.domain_risk.items:
        lines.append("Domain risk:")
        for item in evidence.domain_risk.items:
            if item.risk_flags:
                lines.append(f"- {item.domain}: {', '.join(item.risk_flags)}")
    if evidence.semantic:
        lines.append(
            f"Semantic: intent={evidence.semantic.intent}, "
            f"urgency={evidence.semantic.urgency}"
        )
    if evidence.attachment_scan and evidence.attachment_scan.items:
        lines.append("Attachments:")
        for item in evidence.attachment_scan.items:
            lines.append(
                f"- {item.sha256}: macro={item.has_macro}, exec={item.is_executable}"
            )
    return "\n".join(lines) if lines else "No evidence extracted."


def analyze_email(raw_email: str) -> tuple[str, str, str, str, str]:
    orchestrator = AgentOrchestrator()
    state = orchestrator.detect_raw(raw_email)
    summary = state.email.summary() if state.email else "Unknown email"
    decision = f"{state.verdict} (score={state.risk_score})"
    evidence_human = _humanize_evidence(state.evidence)
    evidence_json = json.dumps(state.evidence.model_dump(), indent=2, ensure_ascii=True)
    report_md = build_report(state)
    return summary, decision, report_md, evidence_human, evidence_json


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
