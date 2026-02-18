"""Centralized policy parameters for planner/judge/router stages."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PipelinePolicy:
    pre_score_review_threshold: int = 30
    pre_score_deep_threshold: int = 70
    context_trigger_score: int = 35
    suspicious_min_score: int = 30
    suspicious_max_score: int = 34
    judge_promote_low_to_suspicious_confidence: float = 0.75
    judge_override_mid_band_confidence: float = 0.58
    judge_allow_mode: str = "never"
    judge_allow_sample_rate: float = 0.0
    judge_allow_sample_salt: str = "argis"

    def normalized(self) -> "PipelinePolicy":
        review = max(1, int(self.pre_score_review_threshold))
        deep = max(review, int(self.pre_score_deep_threshold))
        context = max(1, int(self.context_trigger_score))
        suspicious_min = max(1, int(self.suspicious_min_score))
        suspicious_max = max(suspicious_min, int(self.suspicious_max_score))
        allow_mode = str(self.judge_allow_mode or "").strip().lower()
        if allow_mode not in {"never", "sampled", "always"}:
            allow_mode = "never"
        return PipelinePolicy(
            pre_score_review_threshold=review,
            pre_score_deep_threshold=deep,
            context_trigger_score=context,
            suspicious_min_score=suspicious_min,
            suspicious_max_score=suspicious_max,
            judge_promote_low_to_suspicious_confidence=max(
                0.0, min(1.0, float(self.judge_promote_low_to_suspicious_confidence))
            ),
            judge_override_mid_band_confidence=max(
                0.0, min(1.0, float(self.judge_override_mid_band_confidence))
            ),
            judge_allow_mode=allow_mode,
            judge_allow_sample_rate=max(0.0, min(1.0, float(self.judge_allow_sample_rate))),
            judge_allow_sample_salt=str(self.judge_allow_sample_salt or "argis"),
        )
