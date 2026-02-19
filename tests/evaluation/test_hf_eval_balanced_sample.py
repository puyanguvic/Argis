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
DATASET_FILE = "Phishing_Email.parquet"
POSITIVE_SAMPLE_SIZE = 50
NEGATIVE_SAMPLE_SIZE = 50
SAMPLE_SIZE = POSITIVE_SAMPLE_SIZE + NEGATIVE_SAMPLE_SIZE
RANDOM_SEED = 20250213
TARGET_PROFILE = "ollama"
TARGET_PROVIDER = "local"
TARGET_MODEL = "ollama/qwen2.5:7b"
POSITIVE_LABEL = 1
NEGATIVE_LABEL = 0
LABEL_KEY_CANDIDATES = [
    "label",
    "labels",
    "Label",
    "target",
    "Target",
    "class",
    "Class",
    "is_phishing",
    "Is_Phishing",
    "phishing",
    "Phishing",
    "email_type",
    "Email Type",
    "Category",
    "category",
    "ground_truth",
    "Ground Truth",
    "ground_truth_label",
    "Ground Truth Label",
]
MAX_FALLBACK_RATE = 0.05
MIN_STRICT_RECALL = float(os.getenv("MY_AGENT_EVAL_MIN_STRICT_RECALL", "0.60"))

datasets = pytest.importorskip("datasets")
load_dataset = datasets.load_dataset


def _load_dataset_split():
    data_files = {"eval": f"hf://datasets/{DATASET_ID}/{DATASET_FILE}"}
    dataset = load_dataset("parquet", data_files=data_files, split="eval")
    return dataset, DATASET_FILE


def _to_clean_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).strip().lower() if ch.isalnum())


_LABEL_NORMALIZED_KEYS = {
    _normalize_key(key)
    for key in LABEL_KEY_CANDIDATES
}
_LABEL_NORMALIZED_KEYS.update(
    {
        "label",
        "labels",
        "target",
        "class",
        "isphishing",
        "phishing",
        "emailtype",
        "category",
        "groundtruth",
        "groundtruthlabel",
    }
)


def _is_label_key(key: object) -> bool:
    return _normalize_key(key) in _LABEL_NORMALIZED_KEYS


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
        [
            "text",
            "Text",
            "body",
            "Body",
            "content",
            "Content",
            "email",
            "Email",
            "message",
            "Message",
            "email_text",
            "Email Text",
        ],
    )
    if subject and body:
        return f"Subject: {subject}\n\n{body}"
    if subject or body:
        return subject or body

    fallback_parts: list[str] = []
    for key, value in row.items():
        if str(key).strip().lower() in {"id", "index"} or _is_label_key(key):
            continue
        text = _to_clean_text(value)
        if text:
            fallback_parts.append(f"{key}: {text}")
    fallback = "\n".join(fallback_parts).strip()
    assert fallback, f"No usable text fields were found in a {DATASET_FILE} sample row."
    return fallback


def _normalize_binary_label(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        if value in {NEGATIVE_LABEL, POSITIVE_LABEL}:
            return value
        return None
    if isinstance(value, float):
        if value in {float(NEGATIVE_LABEL), float(POSITIVE_LABEL)}:
            return int(value)
        return None

    text = _to_clean_text(value).lower()
    if not text:
        return None
    compact = "".join(ch for ch in text if ch.isalnum())
    if text in {"1", "1.0", "phishing", "phish", "spam", "malicious", "true", "yes"}:
        return POSITIVE_LABEL
    if text in {"0", "0.0", "benign", "ham", "legit", "legitimate", "normal", "false", "no"}:
        return NEGATIVE_LABEL
    if compact in {"safeemail", "nonphishingemail", "legitemail", "hamemail"}:
        return NEGATIVE_LABEL
    if compact in {"phishingemail", "maliciousemail", "spamemail"}:
        return POSITIVE_LABEL
    if "safe" in text:
        return NEGATIVE_LABEL
    if "phish" in text or "malicious" in text or "spam" in text:
        return POSITIVE_LABEL
    return None


def _extract_label(row: dict) -> int:
    for key in LABEL_KEY_CANDIDATES:
        if key not in row:
            continue
        parsed = _normalize_binary_label(row.get(key))
        if parsed is not None:
            return parsed

    for key, value in row.items():
        if not _is_label_key(key):
            continue
        parsed = _normalize_binary_label(value)
        if parsed is not None:
            return parsed

    raise AssertionError(
        f"No binary label found in row. Tried keys={LABEL_KEY_CANDIDATES}. "
        f"Available keys={list(row.keys())}"
    )


def _sample_balanced_indices(
    dataset,
    *,
    positive_sample_size: int,
    negative_sample_size: int,
    seed: int,
) -> list[int]:
    positive_indices: list[int] = []
    negative_indices: list[int] = []

    for idx, row in enumerate(dataset):
        label = _extract_label(row)
        if label == POSITIVE_LABEL:
            positive_indices.append(idx)
        elif label == NEGATIVE_LABEL:
            negative_indices.append(idx)

    assert len(positive_indices) >= positive_sample_size, (
        f"Dataset {DATASET_ID}/{DATASET_FILE} has only {len(positive_indices)} positive rows, "
        f"but requested {positive_sample_size}."
    )
    assert len(negative_indices) >= negative_sample_size, (
        f"Dataset {DATASET_ID}/{DATASET_FILE} has only {len(negative_indices)} negative rows, "
        f"but requested {negative_sample_size}."
    )

    rng = random.Random(seed)
    selected = rng.sample(positive_indices, positive_sample_size) + rng.sample(negative_indices, negative_sample_size)
    rng.shuffle(selected)
    return selected


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


def test_hf_phishing_email_balanced_sample(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", TARGET_PROFILE)
    monkeypatch.delenv("MY_AGENT_APP_PROVIDER", raising=False)
    monkeypatch.delenv("MY_AGENT_APP_MODEL", raising=False)
    _assert_remote_model_ready()
    print(
        f"[hf-balanced-test] env python={sys.executable} "
        f"agents={importlib.util.find_spec('agents') is not None} "
        f"ollama_url=http://127.0.0.1:11434"
    )

    try:
        dataset, split_used = _load_dataset_split()
    except Exception as exc:
        pytest.skip(f"Cannot load dataset {DATASET_ID}: {exc}")

    selected_indices = _sample_balanced_indices(
        dataset,
        positive_sample_size=POSITIVE_SAMPLE_SIZE,
        negative_sample_size=NEGATIVE_SAMPLE_SIZE,
        seed=RANDOM_SEED,
    )
    sampled = dataset.select(selected_indices)

    gold_labels = [_extract_label(row) for row in sampled]
    gold_distribution = Counter(gold_labels)
    assert gold_distribution[POSITIVE_LABEL] == POSITIVE_SAMPLE_SIZE
    assert gold_distribution[NEGATIVE_LABEL] == NEGATIVE_SAMPLE_SIZE

    pred_labels_strict: list[int] = []
    risk_scores: list[int] = []
    runtime_models: set[str] = set()
    runtime_providers: set[str] = set()
    provider_used_values: list[str] = []
    verdict_values: list[str] = []

    print("[hf-balanced-test] per-case results")
    for case_no, (row, gold_label) in enumerate(zip(sampled, gold_labels), start=1):
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
        risk_score = int(output.get("risk_score", 0))
        risk_scores.append(risk_score)
        subject = _truncate(_first_non_empty_value(row, ["subject", "Subject", "title", "Title"]))
        print(
            f"[hf-balanced-test] case={case_no:03d} gold={gold_label} pred_strict={pred_labels_strict[-1]} "
            f"verdict={verdict} risk={risk_score:3d} "
            f"provider_used={provider_used or 'unknown'} subject={subject!r}"
        )

    verdict_counter = Counter(verdict_values)
    assert len(pred_labels_strict) == SAMPLE_SIZE
    assert runtime_models == {TARGET_MODEL}
    assert runtime_providers == {TARGET_PROVIDER}

    strict = _compute_binary_metrics(
        gold_labels=gold_labels,
        pred_labels=pred_labels_strict,
        positive_label=POSITIVE_LABEL,
        negative_label=NEGATIVE_LABEL,
    )
    strict_recall = float(strict["recall"])
    predicted_phishing = int(strict["predicted_positive"])
    avg_risk = sum(risk_scores) / SAMPLE_SIZE if risk_scores else 0.0
    fallback_count = sum(1 for item in provider_used_values if item.endswith(":fallback"))
    fallback_rate = _safe_ratio(fallback_count, SAMPLE_SIZE)

    print(
        f"[hf-balanced-test] dataset={DATASET_ID} file={DATASET_FILE} split_used={split_used} "
        f"sampled={SAMPLE_SIZE} seed={RANDOM_SEED} "
        f"positives={POSITIVE_SAMPLE_SIZE} negatives={NEGATIVE_SAMPLE_SIZE} "
        f"profile={TARGET_PROFILE} "
        f"provider={TARGET_PROVIDER} model={TARGET_MODEL}"
    )
    print(
        f"[hf-balanced-test] strict_accuracy={strict['accuracy']:.4f} "
        f"strict_precision={strict['precision']:.4f} strict_recall={strict_recall:.4f} "
        f"strict_specificity={strict['specificity']:.4f} predicted_phishing={predicted_phishing} "
        f"false_negatives={strict['fn']} false_positives={strict['fp']}"
    )
    print(
        f"[hf-balanced-test] avg_risk={avg_risk:.2f}"
    )
    print(
        f"[hf-balanced-test] fallback_count={fallback_count} fallback_rate={fallback_rate:.4f} "
        f"max_allowed_fallback_rate={MAX_FALLBACK_RATE:.4f}"
    )
    print("[hf-balanced-test] summary metrics table")
    print("| metric | value |")
    print("|---|---:|")
    print(f"| strict_accuracy | {strict['accuracy']:.4f} |")
    print(f"| strict_precision | {strict['precision']:.4f} |")
    print(f"| strict_recall | {strict_recall:.4f} |")
    print(f"| strict_specificity | {strict['specificity']:.4f} |")
    print(f"| strict_false_positive | {strict['fp']} |")
    print(f"| strict_false_negative | {strict['fn']} |")
    print(f"| gold_distribution | {dict(gold_distribution)} |")
    print(f"| verdict_distribution | {dict(verdict_counter)} |")
    print(f"| avg_risk | {avg_risk:.2f} |")
    print(f"| fallback_count | {fallback_count} |")
    print(f"| fallback_rate | {fallback_rate:.4f} |")

    assert fallback_rate <= MAX_FALLBACK_RATE, (
        f"Fallback rate too high: {fallback_rate:.4f} > {MAX_FALLBACK_RATE:.4f}. "
        "This run did not reliably execute the remote model path."
    )
    assert strict_recall >= MIN_STRICT_RECALL, (
        f"Strict recall is too low: {strict_recall:.4f} < {MIN_STRICT_RECALL:.4f}. "
        "The agent is missing too many known phishing emails."
    )
