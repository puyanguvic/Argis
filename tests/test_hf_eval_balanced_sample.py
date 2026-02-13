import json
import importlib.util
import os
import random
import sys
from urllib.error import URLError
from urllib.request import urlopen
from collections import Counter

import pytest

from phish_email_detection_agent.cli import run_once

DATASET_ID = "puyang2025/seven-phishing-email-datasets"
SAMPLE_SIZE = 100
HALF_SAMPLE_SIZE = SAMPLE_SIZE // 2
RANDOM_SEED = 20250213
TARGET_PROFILE = "ollama"
TARGET_PROVIDER = "local"
TARGET_MODEL = "ollama/qwen2.5:7b"
MAX_FALLBACK_RATE = 0.05
MAX_SUSPICIOUS_RATE = float(os.getenv("MY_AGENT_EVAL_MAX_SUSPICIOUS_RATE", "0.30"))

datasets = pytest.importorskip("datasets")
load_dataset = datasets.load_dataset


def _load_eval_like_split():
    data_files = {"eval": f"hf://datasets/{DATASET_ID}/eval.parquet"}
    dataset = load_dataset("parquet", data_files=data_files, split="eval")
    return dataset, "eval.parquet"


def _build_input_text(row: dict) -> str:
    subject = str(row.get("subject") or "").strip()
    body = str(row.get("text") or "").strip()
    if subject and body:
        return f"Subject: {subject}\n\n{body}"
    return subject or body


def _sample_balanced_indices(labels: list[int], seed: int) -> tuple[list[int], int, int]:
    values = [int(v) for v in labels]
    label_values = sorted(set(values))
    assert len(label_values) == 2, f"Expected binary labels, got {label_values}."
    negative_label, positive_label = label_values[0], label_values[1]

    negative_indices = [idx for idx, value in enumerate(values) if value == negative_label]
    positive_indices = [idx for idx, value in enumerate(values) if value == positive_label]
    assert len(negative_indices) >= HALF_SAMPLE_SIZE
    assert len(positive_indices) >= HALF_SAMPLE_SIZE

    rng = random.Random(seed)
    selected = rng.sample(negative_indices, HALF_SAMPLE_SIZE) + rng.sample(
        positive_indices, HALF_SAMPLE_SIZE
    )
    rng.shuffle(selected)
    return selected, negative_label, positive_label


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


def test_hf_eval_balanced_100_cases(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", TARGET_PROFILE)
    monkeypatch.delenv("MY_AGENT_APP_PROVIDER", raising=False)
    monkeypatch.delenv("MY_AGENT_APP_MODEL", raising=False)
    _assert_remote_model_ready()
    print(
        f"[hf-balance-test] env python={sys.executable} "
        f"agents={importlib.util.find_spec('agents') is not None} "
        f"ollama_url=http://127.0.0.1:11434"
    )

    try:
        dataset, split_used = _load_eval_like_split()
    except Exception as exc:
        pytest.skip(f"Cannot load dataset {DATASET_ID}: {exc}")

    selected_indices, negative_label, positive_label = _sample_balanced_indices(
        dataset["label"], seed=RANDOM_SEED
    )
    sampled = dataset.select(selected_indices)

    gold_labels: list[int] = []
    pred_labels_strict: list[int] = []
    pred_labels_relaxed: list[int] = []
    risk_scores: list[int] = []
    runtime_models: set[str] = set()
    runtime_providers: set[str] = set()
    provider_used_values: list[str] = []
    verdict_values: list[str] = []

    print("[hf-balance-test] per-case results")
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
        pred_label_strict = positive_label if verdict == "phishing" else negative_label
        pred_label_relaxed = positive_label if verdict in {"phishing", "suspicious"} else negative_label
        gold_label = int(row["label"])
        gold_labels.append(gold_label)
        pred_labels_strict.append(pred_label_strict)
        pred_labels_relaxed.append(pred_label_relaxed)
        risk_score = int(output.get("risk_score", 0))
        risk_scores.append(risk_score)
        is_hit = gold_label == pred_label_strict
        subject = _truncate(str(row.get("subject") or "").strip())
        print(
            f"[hf-balance-test] case={case_no:03d} gold={gold_label} pred={pred_label_strict} "
            f"verdict={verdict} risk={risk_score:3d} hit={'Y' if is_hit else 'N'} "
            f"provider_used={provider_used or 'unknown'} "
            f"subject={subject!r}"
        )

    sampled_counter = Counter(gold_labels)
    verdict_counter = Counter(verdict_values)
    assert len(gold_labels) == SAMPLE_SIZE
    assert sampled_counter[negative_label] == HALF_SAMPLE_SIZE
    assert sampled_counter[positive_label] == HALF_SAMPLE_SIZE
    assert len(pred_labels_strict) == SAMPLE_SIZE
    assert len(pred_labels_relaxed) == SAMPLE_SIZE
    assert runtime_models == {TARGET_MODEL}
    assert runtime_providers == {TARGET_PROVIDER}

    strict = _compute_binary_metrics(
        gold_labels=gold_labels,
        pred_labels=pred_labels_strict,
        positive_label=positive_label,
        negative_label=negative_label,
    )
    relaxed = _compute_binary_metrics(
        gold_labels=gold_labels,
        pred_labels=pred_labels_relaxed,
        positive_label=positive_label,
        negative_label=negative_label,
    )

    predicted_phishing = int(strict["predicted_positive"])
    predicted_phish_or_suspicious = int(relaxed["predicted_positive"])
    suspicious_count = int(verdict_counter.get("suspicious", 0))
    suspicious_rate = _safe_ratio(suspicious_count, SAMPLE_SIZE)
    avg_risk = sum(risk_scores) / SAMPLE_SIZE if risk_scores else 0.0
    fallback_count = sum(1 for item in provider_used_values if item.endswith(":fallback"))
    fallback_rate = _safe_ratio(fallback_count, SAMPLE_SIZE)

    print(
        f"[hf-balance-test] dataset={DATASET_ID} split_used={split_used} sampled={SAMPLE_SIZE} "
        f"label_balance={dict(sampled_counter)} seed={RANDOM_SEED} "
        f"profile={TARGET_PROFILE} provider={TARGET_PROVIDER} model={TARGET_MODEL}"
    )
    print(
        f"[hf-balance-test] strict_accuracy={strict['accuracy']:.4f} "
        f"strict_tp={strict['tp']} strict_tn={strict['tn']} strict_fp={strict['fp']} strict_fn={strict['fn']} "
        f"predicted_phishing={predicted_phishing}"
    )
    print(
        f"[hf-balance-test] relaxed_accuracy={relaxed['accuracy']:.4f} "
        f"relaxed_tp={relaxed['tp']} relaxed_tn={relaxed['tn']} relaxed_fp={relaxed['fp']} relaxed_fn={relaxed['fn']} "
        f"predicted_phishing_or_suspicious={predicted_phish_or_suspicious} "
        f"suspicious_count={suspicious_count} suspicious_rate={suspicious_rate:.4f} "
        f"max_allowed_suspicious_rate={MAX_SUSPICIOUS_RATE:.4f} avg_risk={avg_risk:.2f}"
    )
    print(
        f"[hf-balance-test] fallback_count={fallback_count} fallback_rate={fallback_rate:.4f} "
        f"max_allowed_fallback_rate={MAX_FALLBACK_RATE:.4f}"
    )
    print("[hf-balance-test] summary metrics table")
    print("| metric | value |")
    print("|---|---:|")
    print(f"| strict_accuracy | {strict['accuracy']:.4f} |")
    print(f"| strict_precision | {strict['precision']:.4f} |")
    print(f"| strict_recall | {strict['recall']:.4f} |")
    print(f"| strict_specificity | {strict['specificity']:.4f} |")
    print(f"| strict_f1 | {strict['f1']:.4f} |")
    print(f"| strict_tp | {strict['tp']} |")
    print(f"| strict_tn | {strict['tn']} |")
    print(f"| strict_fp | {strict['fp']} |")
    print(f"| strict_fn | {strict['fn']} |")
    print(f"| relaxed_accuracy | {relaxed['accuracy']:.4f} |")
    print(f"| relaxed_precision | {relaxed['precision']:.4f} |")
    print(f"| relaxed_recall | {relaxed['recall']:.4f} |")
    print(f"| relaxed_specificity | {relaxed['specificity']:.4f} |")
    print(f"| relaxed_f1 | {relaxed['f1']:.4f} |")
    print(f"| relaxed_tp | {relaxed['tp']} |")
    print(f"| relaxed_tn | {relaxed['tn']} |")
    print(f"| relaxed_fp | {relaxed['fp']} |")
    print(f"| relaxed_fn | {relaxed['fn']} |")
    print(f"| predicted_phishing | {predicted_phishing} |")
    print(f"| predicted_phishing_or_suspicious | {predicted_phish_or_suspicious} |")
    print(f"| suspicious_count | {suspicious_count} |")
    print(f"| suspicious_rate | {suspicious_rate:.4f} |")
    print(f"| max_allowed_suspicious_rate | {MAX_SUSPICIOUS_RATE:.4f} |")
    print(f"| verdict_distribution | {dict(verdict_counter)} |")
    print(f"| avg_risk | {avg_risk:.2f} |")
    print(f"| fallback_count | {fallback_count} |")
    print(f"| fallback_rate | {fallback_rate:.4f} |")
    print(f"| max_allowed_fallback_rate | {MAX_FALLBACK_RATE:.4f} |")

    assert fallback_rate <= MAX_FALLBACK_RATE, (
        f"Fallback rate too high: {fallback_rate:.4f} > {MAX_FALLBACK_RATE:.4f}. "
        "This run did not reliably execute the remote model path."
    )
    assert suspicious_rate <= MAX_SUSPICIOUS_RATE, (
        f"Suspicious rate too high: {suspicious_rate:.4f} > {MAX_SUSPICIOUS_RATE:.4f}. "
        "Tune verdict calibration or suspicious score window."
    )
