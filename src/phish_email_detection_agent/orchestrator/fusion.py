"""Risk fusion layer for multi-modal phishing evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FusionWeights:
    text: float = 0.22
    url: float = 0.24
    domain: float = 0.18
    attachment: float = 0.26
    ocr: float = 0.10

    def normalize(self) -> "FusionWeights":
        total = self.text + self.url + self.domain + self.attachment + self.ocr
        if total <= 0:
            return FusionWeights()
        return FusionWeights(
            text=self.text / total,
            url=self.url / total,
            domain=self.domain / total,
            attachment=self.attachment / total,
            ocr=self.ocr / total,
        )


def _bounded_score(raw: Any) -> int:
    try:
        value = int(float(raw))
    except (TypeError, ValueError):
        return 0
    if value < 0:
        return 0
    if value > 100:
        return 100
    return value


def fuse_risk_scores(
    *,
    text_score: int,
    url_score: int,
    domain_score: int,
    attachment_score: int,
    ocr_score: int,
    weights: FusionWeights | None = None,
) -> dict[str, Any]:
    norm = (weights or FusionWeights()).normalize()
    weighted = (
        _bounded_score(text_score) * norm.text
        + _bounded_score(url_score) * norm.url
        + _bounded_score(domain_score) * norm.domain
        + _bounded_score(attachment_score) * norm.attachment
        + _bounded_score(ocr_score) * norm.ocr
    )
    score = max(0, min(100, int(round(weighted))))
    if score >= 70:
        level = "high"
    elif score >= 35:
        level = "medium"
    else:
        level = "low"
    verdict = "phishing" if score >= 35 else "benign"
    return {"risk_score": score, "risk_level": level, "verdict": verdict}
