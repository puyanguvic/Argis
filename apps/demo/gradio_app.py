"""Gradio demo app for the phishing email detection agent."""

from __future__ import annotations

import json
import random
from collections import Counter

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


def _normalize_label(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "phishing" if value else "benign"
    if isinstance(value, (int, float)):
        if value == 1:
            return "phishing"
        if value == 0:
            return "benign"
    text = str(value).strip().lower()
    if text in {"phishing", "phish", "spam", "scam", "malicious", "fraud"}:
        return "phishing"
    if text in {"suspicious", "suspect"}:
        return "suspicious"
    if text in {
        "benign",
        "ham",
        "legit",
        "legitimate",
        "normal",
        "clean",
        "non-phishing",
        "nonphishing",
    }:
        return "benign"
    return "unknown"


def _pick_column(columns: list[str], candidates: list[str]) -> str | None:
    lower_map = {name.lower(): name for name in columns}
    for name in candidates:
        if name in columns:
            return name
        lowered = lower_map.get(name)
        if lowered:
            return lowered
    return None


def _load_hf_samples(
    dataset_name: str, seed: int, per_class: int = 50
) -> list[dict[str, object]]:
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise RuntimeError(
            "Missing dependency: datasets. Install with `pip install datasets pyarrow`."
        ) from exc

    dataset = load_dataset(dataset_name)
    if hasattr(dataset, "keys"):
        split_name = "train" if "train" in dataset else list(dataset.keys())[0]
        data = dataset[split_name]
    else:
        data = dataset

    columns = list(data.column_names)
    label_col = _pick_column(
        columns, ["label", "class", "category", "target", "is_phishing", "phishing"]
    )
    text_col = _pick_column(
        columns,
        [
            "raw",
            "raw_email",
            "email",
            "text",
            "content",
            "body",
            "message",
            "mail",
            "mail_body",
        ],
    )
    id_col = _pick_column(columns, ["id", "email_id", "uid", "message_id"])

    if not label_col or not text_col:
        raise RuntimeError(
            "Could not find label/text columns in dataset. "
            f"columns={columns}, label_col={label_col}, text_col={text_col}"
        )

    benign_indices: list[int] = []
    phishing_indices: list[int] = []
    for idx in range(len(data)):
        label = _normalize_label(data[idx].get(label_col))
        if label == "benign":
            benign_indices.append(idx)
        elif label == "phishing":
            phishing_indices.append(idx)

    if len(benign_indices) < per_class or len(phishing_indices) < per_class:
        raise RuntimeError(
            f"Not enough labeled samples to draw {per_class} per class. "
            f"benign={len(benign_indices)}, phishing={len(phishing_indices)}"
        )

    rng = random.Random(seed)
    selected = rng.sample(benign_indices, per_class) + rng.sample(
        phishing_indices, per_class
    )
    rng.shuffle(selected)

    samples: list[dict[str, object]] = []
    for idx in selected:
        row = data[idx]
        samples.append(
            {
                "sample_id": row.get(id_col) if id_col else idx,
                "label": _normalize_label(row.get(label_col)),
                "raw_email": row.get(text_col),
            }
        )
    return samples


def _predict_verdict(raw_email: str) -> tuple[str, int | None, str]:
    events = ENGINE.submit(
        UserInput(session_id="gradio", input_kind="raw_email", payload=raw_email)
    )
    artifacts = _extract_task_artifacts(events)
    payload = artifacts.get("detection_result") or {}
    verdict = payload.get("verdict") or "unknown"
    risk_score = payload.get("risk_score")
    summary = payload.get("summary") or ""
    return verdict, risk_score, summary


def _format_confusion_matrix(counts: Counter[tuple[str, str]]) -> str:
    true_labels = ["benign", "phishing"]
    pred_labels = ["benign", "phishing", "suspicious", "unknown"]
    header = "| true\\pred | " + " | ".join(pred_labels) + " |"
    sep = "|---|" + "|".join(["---"] * len(pred_labels)) + "|"
    rows = [header, sep]
    for true_label in true_labels:
        values = [str(counts.get((true_label, pred), 0)) for pred in pred_labels]
        rows.append("| " + true_label + " | " + " | ".join(values) + " |")
    return "\n".join(rows)


def run_benchmark(
    dataset_name: str, seed: int, total_samples: int
) -> tuple[str, list[list[object]], str]:
    if total_samples <= 0 or total_samples % 2 != 0:
        return "Error: sample size must be a positive even number.", [], ""
    per_class = total_samples // 2
    try:
        samples = _load_hf_samples(dataset_name, seed, per_class=per_class)
    except RuntimeError as exc:
        return f"Error: {exc}", [], ""

    rows: list[list[object]] = []
    strict_hits = 0
    verdict_counts: Counter[str] = Counter()
    confusion_counts: Counter[tuple[str, str]] = Counter()
    for sample in samples:
        verdict, risk_score, _summary = _predict_verdict(sample["raw_email"])
        normalized_verdict = _normalize_label(verdict)
        verdict_counts[normalized_verdict] += 1
        true_label = sample["label"]
        strict_correct = normalized_verdict == true_label
        strict_hits += int(strict_correct)
        confusion_counts[(true_label, normalized_verdict)] += 1
        rows.append(
            [
                sample["sample_id"],
                true_label,
                normalized_verdict,
                "yes" if strict_correct else "no",
                risk_score,
            ]
        )

    total = len(samples)
    summary = (
        f"Samples: {total} ({per_class} benign, {per_class} phishing). "
        "Verdict 'suspicious' counts as incorrect.\n"
        f"Accuracy (strict): {strict_hits}/{total} = {strict_hits / total:.2%}\n"
        f"Verdict counts: {dict(verdict_counts)}"
    )
    confusion_md = _format_confusion_matrix(confusion_counts)
    return summary, rows, confusion_md


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

        gr.Markdown("## Batch benchmark (Hugging Face dataset)")
        gr.Markdown(
            "Click to sample 50 benign + 50 phishing emails from a dataset and "
            "run the agent. No email content is shown in the results table."
        )
        dataset_name = gr.Textbox(
            label="Dataset",
            value="puyang2025/seven-phishing-email-datasets",
        )
        total_samples = gr.Number(
            label="Sample size (even number)", value=100, precision=0
        )
        seed = gr.Number(label="Random seed", value=42, precision=0)
        bench_btn = gr.Button("Run benchmark")
        bench_summary = gr.Textbox(label="Benchmark Summary", lines=4)
        bench_table = gr.Dataframe(
            headers=[
                "sample_id",
                "true_label",
                "verdict",
                "correct",
                "risk_score",
            ],
            interactive=False,
        )
        confusion_md = gr.Markdown(label="Confusion Matrix")

        bench_btn.click(
            run_benchmark,
            inputs=[dataset_name, seed, total_samples],
            outputs=[bench_summary, bench_table, confusion_md],
        )
    return demo


if __name__ == "__main__":
    build_demo().launch(share=True)
