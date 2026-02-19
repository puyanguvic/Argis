"""Offline evaluator for verdict calibration and regression tracking."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


@dataclass(frozen=True)
class OfflineEvaluation:
    total: int
    positives: int
    negatives: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
    accuracy: float
    precision: float
    recall: float
    f1: float


class OfflineEvaluator:
    """Compute binary classification metrics for offline experiments."""

    def __init__(
        self,
        *,
        positive_label: str = "phishing",
        negative_label: str = "benign",
        suspicious_as_positive: bool = True,
    ) -> None:
        self.positive_label = str(positive_label).strip().lower() or "phishing"
        self.negative_label = str(negative_label).strip().lower() or "benign"
        self.suspicious_as_positive = bool(suspicious_as_positive)

    def to_binary_label(self, verdict: str) -> str:
        normalized = str(verdict).strip().lower()
        if normalized == "suspicious":
            return self.positive_label if self.suspicious_as_positive else self.negative_label
        if normalized == self.positive_label:
            return self.positive_label
        return self.negative_label

    def evaluate_verdicts(self, *, predicted: list[str], truth: list[str]) -> OfflineEvaluation:
        if len(predicted) != len(truth):
            raise ValueError("`predicted` and `truth` must have the same length.")

        tp = tn = fp = fn = 0
        for pred_raw, truth_raw in zip(predicted, truth, strict=True):
            pred = self.to_binary_label(pred_raw)
            target = self.to_binary_label(truth_raw)
            if pred == self.positive_label and target == self.positive_label:
                tp += 1
            elif pred == self.negative_label and target == self.negative_label:
                tn += 1
            elif pred == self.positive_label and target == self.negative_label:
                fp += 1
            else:
                fn += 1

        total = len(predicted)
        positives = sum(1 for item in truth if self.to_binary_label(item) == self.positive_label)
        negatives = total - positives
        accuracy = _safe_div(tp + tn, total)
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        return OfflineEvaluation(
            total=total,
            positives=positives,
            negatives=negatives,
            true_positive=tp,
            true_negative=tn,
            false_positive=fp,
            false_negative=fn,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
        )

    def evaluate_records(
        self,
        records: list[dict[str, Any]],
        *,
        prediction_key: str = "verdict",
        truth_key: str = "label",
    ) -> OfflineEvaluation:
        predicted = [str(item.get(prediction_key, "")) for item in records]
        truth = [str(item.get(truth_key, "")) for item in records]
        return self.evaluate_verdicts(predicted=predicted, truth=truth)
