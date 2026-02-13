import importlib.util
import json
import os
import random
import sys
from collections import Counter
from urllib.error import URLError
from urllib.request import urlopen

import pytest

from phish_email_detection_agent.cli import run_once

DATASET_ID = "puyang2025/phish-email-datasets"
DATASET_FILE = "Nazario.parquet"
SAMPLE_SIZE = 100
RANDOM_SEED = 20250213
TARGET_PROFILE = "ollama"
TARGET_PROVIDER = "local"
TARGET_MODEL = "ollama/qwen2.5:7b"
POSITIVE_LABEL = 1
NEGATIVE_LABEL = 0
MAX_FALLBACK_RATE = 0.05
MAX_SUSPICIOUS_RATE = float(os.getenv("MY_AGENT_EVAL_MAX_SUSPICIOUS_RATE", "0.30"))
MIN_STRICT_RECALL = float(os.getenv("MY_AGENT_EVAL_MIN_STRICT_RECALL", "0.60"))
ALLOW_SUSPICIOUS_VERDICT = (
    str(os.getenv("MY_AGENT_EVAL_ALLOW_SUSPICIOUS", "0")).strip().lower() in {"1", "true", "yes", "on"}
)
_default_min_relaxed = "0.90" if ALLOW_SUSPICIOUS_VERDICT else str(MIN_STRICT_RECALL)
MIN_RELAXED_RECALL = float(os.getenv("MY_AGENT_EVAL_MIN_RELAXED_RECALL", _default_min_relaxed))

datasets = pytest.importorskip("datasets")
load_dataset = datasets.load_dataset


def _load_nazario_split():
    data_files = {"eval": f"hf://datasets/{DATASET_ID}/{DATASET_FILE}"}
    dataset = load_dataset("parquet", data_files=data_files, split="eval")
    return dataset, DATASET_FILE


def _to_clean_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _first_non_empty_value(row: dict, candidates: list[str]) -> str:
    for key in candidates:
        if key in row:
            text = _to_clean_text(row.get(key))
            if text:
                return text
    return ""


def _build_input_text(row: dict) -> str:
    subject = _first_non_empty_value(row, ["subject", "Subject", "title", "Title"])
    body = _first_non_empty_value(
        row,
        ["text", "Text", "body", "Body", "content", "Content", "email", "Email", "message", "Message"],
    )
    if subject and body:
        return f"Subject: {subject}\n\n{body}"
    if subject or body:
        return subject or body

    fallback_parts: list[str] = []
    for key, value in row.items():
        if str(key).strip().lower() in {"label", "id", "index"}:
            continue
        text = _to_clean_text(value)
        if text:
            fallback_parts.append(f"{key}: {text}")
    fallback = "\n".join(fallback_parts).strip()
    assert fallback, "No usable text fields were found in a Nazario sample row."
    return fallback


def _sample_random_indices(total_size: int, sample_size: int, seed: int) -> list[int]:
    assert total_size >= sample_size, (
        f"Dataset {DATASET_ID}/{DATASET_FILE} has only {total_size} rows, "
        f"but SAMPLE_SIZE is {sample_size}."
    )
    rng = random.Random(seed)
    return rng.sample(list(range(total_size)), sample_size)


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _truncate(text: str, limit: int = 56) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _compute_binary_metrics(
    *,
    gold_labels: list[int],
    pred_labels: list[int],
    positive_label: int,
    negative_label: int,
) -> dict[str, float | int]:
    tp = sum(1 for y, p in zip(gold_labels, pred_labels) if y == positive_label and p == positive_label)
    tn = sum(1 for y, p in zip(gold_labels, pred_labels) if y == negative_label and p == negative_label)
    fp = sum(1 for y, p in zip(gold_labels, pred_labels) if y == negative_label and p == positive_label)
    fn = sum(1 for y, p in zip(gold_labels, pred_labels) if y == positive_label and p == negative_label)
    accuracy = _safe_ratio(tp + tn, len(gold_labels))
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    specificity = _safe_ratio(tn, tn + fp)
    f1 = _safe_ratio(2 * precision * recall, precision + recall)
    predicted_positive = sum(1 for label in pred_labels if label == positive_label)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "predicted_positive": predicted_positive,
    }


def _assert_remote_model_ready() -> None:
    if importlib.util.find_spec("agents") is None:
        pytest.fail(
            "Current test interpreter is missing `agents` package. "
            f"python={sys.executable}. "
            "Use the project venv and run `python -m pytest ...`, "
            "or install dependencies into this interpreter."
        )
    try:
        with urlopen("http://127.0.0.1:11434/api/tags", timeout=3.0) as resp:
            if getattr(resp, "status", 200) >= 400:
                raise URLError(f"HTTP {resp.status}")
    except Exception as exc:
        pytest.fail(
            "Ollama is not reachable at http://127.0.0.1:11434. "
            f"python={sys.executable}. error={exc!r}"
        )


def test_hf_nazario_100_phishing_cases(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", TARGET_PROFILE)
    monkeypatch.delenv("MY_AGENT_APP_PROVIDER", raising=False)
    monkeypatch.delenv("MY_AGENT_APP_MODEL", raising=False)
    _assert_remote_model_ready()
    print(
        f"[hf-nazario-test] env python={sys.executable} "
        f"agents={importlib.util.find_spec('agents') is not None} "
        f"ollama_url=http://127.0.0.1:11434 "
        f"allow_suspicious_verdict={ALLOW_SUSPICIOUS_VERDICT}"
    )

    try:
        dataset, split_used = _load_nazario_split()
    except Exception as exc:
        pytest.skip(f"Cannot load dataset {DATASET_ID}: {exc}")

    selected_indices = _sample_random_indices(len(dataset), SAMPLE_SIZE, seed=RANDOM_SEED)
    sampled = dataset.select(selected_indices)

    gold_labels = [POSITIVE_LABEL] * SAMPLE_SIZE
    pred_labels_strict: list[int] = []
    pred_labels_relaxed: list[int] = []
    risk_scores: list[int] = []
    runtime_models: set[str] = set()
    runtime_providers: set[str] = set()
    provider_used_values: list[str] = []
    verdict_values: list[str] = []

    print("[hf-nazario-test] per-case results")
    for case_no, row in enumerate(sampled, start=1):
        payload = _build_input_text(row)
        output = json.loads(run_once(payload, model=TARGET_MODEL))
        runtime = output.get("runtime", {})
        runtime_models.add(str(runtime.get("model", "")))
        runtime_providers.add(str(runtime.get("provider", "")))
        provider_used = str(output.get("provider_used", ""))
        provider_used_values.append(provider_used)
        verdict = str(output.get("verdict", "benign")).strip().lower()
        verdict_values.append(verdict)
        pred_labels_strict.append(POSITIVE_LABEL if verdict == "phishing" else NEGATIVE_LABEL)
        if ALLOW_SUSPICIOUS_VERDICT:
            pred_labels_relaxed.append(
                POSITIVE_LABEL if verdict in {"phishing", "suspicious"} else NEGATIVE_LABEL
            )
        else:
            pred_labels_relaxed.append(POSITIVE_LABEL if verdict == "phishing" else NEGATIVE_LABEL)
        risk_score = int(output.get("risk_score", 0))
        risk_scores.append(risk_score)
        subject = _truncate(_first_non_empty_value(row, ["subject", "Subject", "title", "Title"]))
        print(
            f"[hf-nazario-test] case={case_no:03d} pred_strict={pred_labels_strict[-1]} "
            f"verdict={verdict} risk={risk_score:3d} "
            f"provider_used={provider_used or 'unknown'} subject={subject!r}"
        )

    verdict_counter = Counter(verdict_values)
    assert len(pred_labels_strict) == SAMPLE_SIZE
    assert len(pred_labels_relaxed) == SAMPLE_SIZE
    assert runtime_models == {TARGET_MODEL}
    assert runtime_providers == {TARGET_PROVIDER}

    strict = _compute_binary_metrics(
        gold_labels=gold_labels,
        pred_labels=pred_labels_strict,
        positive_label=POSITIVE_LABEL,
        negative_label=NEGATIVE_LABEL,
    )
    relaxed = _compute_binary_metrics(
        gold_labels=gold_labels,
        pred_labels=pred_labels_relaxed,
        positive_label=POSITIVE_LABEL,
        negative_label=NEGATIVE_LABEL,
    )

    strict_recall = float(strict["recall"])
    relaxed_recall = float(relaxed["recall"])
    predicted_phishing = int(strict["predicted_positive"])
    predicted_phish_or_suspicious = int(relaxed["predicted_positive"])
    suspicious_count = int(verdict_counter.get("suspicious", 0))
    suspicious_rate = _safe_ratio(suspicious_count, SAMPLE_SIZE)
    avg_risk = sum(risk_scores) / SAMPLE_SIZE if risk_scores else 0.0
    fallback_count = sum(1 for item in provider_used_values if item.endswith(":fallback"))
    fallback_rate = _safe_ratio(fallback_count, SAMPLE_SIZE)

    print(
        f"[hf-nazario-test] dataset={DATASET_ID} split_used={split_used} sampled={SAMPLE_SIZE} "
        f"seed={RANDOM_SEED} all_positive=True profile={TARGET_PROFILE} "
        f"provider={TARGET_PROVIDER} model={TARGET_MODEL}"
    )
    print(
        f"[hf-nazario-test] strict_recall={strict_recall:.4f} predicted_phishing={predicted_phishing} "
        f"false_negatives={strict['fn']}"
    )
    print(
        f"[hf-nazario-test] relaxed_recall={relaxed_recall:.4f} "
        f"predicted_phishing_or_suspicious={predicted_phish_or_suspicious} "
        f"suspicious_count={suspicious_count} suspicious_rate={suspicious_rate:.4f} "
        f"max_allowed_suspicious_rate={MAX_SUSPICIOUS_RATE:.4f} avg_risk={avg_risk:.2f}"
    )
    print(
        f"[hf-nazario-test] fallback_count={fallback_count} fallback_rate={fallback_rate:.4f} "
        f"max_allowed_fallback_rate={MAX_FALLBACK_RATE:.4f}"
    )
    print("[hf-nazario-test] summary metrics table")
    print("| metric | value |")
    print("|---|---:|")
    print(f"| strict_recall | {strict_recall:.4f} |")
    print(f"| strict_false_negative | {strict['fn']} |")
    print(f"| relaxed_recall | {relaxed_recall:.4f} |")
    print(f"| suspicious_count | {suspicious_count} |")
    print(f"| suspicious_rate | {suspicious_rate:.4f} |")
    print(f"| verdict_distribution | {dict(verdict_counter)} |")
    print(f"| avg_risk | {avg_risk:.2f} |")
    print(f"| fallback_count | {fallback_count} |")
    print(f"| fallback_rate | {fallback_rate:.4f} |")

    assert fallback_rate <= MAX_FALLBACK_RATE, (
        f"Fallback rate too high: {fallback_rate:.4f} > {MAX_FALLBACK_RATE:.4f}. "
        "This run did not reliably execute the remote model path."
    )
    assert suspicious_rate <= MAX_SUSPICIOUS_RATE, (
        f"Suspicious rate too high: {suspicious_rate:.4f} > {MAX_SUSPICIOUS_RATE:.4f}. "
        "Too many phishing samples landed in the ambiguous bucket."
    )
    if not ALLOW_SUSPICIOUS_VERDICT:
        assert suspicious_count == 0, (
            f"Binary mode expects no 'suspicious' verdict, but got {suspicious_count} / {SAMPLE_SIZE}."
        )
    assert strict_recall >= MIN_STRICT_RECALL, (
        f"Strict recall is too low: {strict_recall:.4f} < {MIN_STRICT_RECALL:.4f}. "
        "The agent is missing too many known phishing emails."
    )
    assert relaxed_recall >= MIN_RELAXED_RECALL, (
        f"Relaxed recall is too low: {relaxed_recall:.4f} < {MIN_RELAXED_RECALL:.4f}. "
        "Even phishing+suspicious detection is below target."
    )
