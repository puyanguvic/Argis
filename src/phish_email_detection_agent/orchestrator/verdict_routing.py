"""Route mapping and verdict calibration helpers."""

from __future__ import annotations

from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy


def map_route_to_path(route: str) -> str:
    return {
        "allow": "FAST",
        "review": "STANDARD",
        "deep": "DEEP",
    }.get(str(route or "").strip().lower(), "STANDARD")


def verdict_from_score(score: int, *, suspicious_min_score: int, suspicious_max_score: int) -> str:
    if score >= 35:
        return "phishing"
    if suspicious_min_score <= score <= suspicious_max_score:
        return "suspicious"
    return "benign"


def normalize_score_for_verdict(
    score: int,
    verdict: str,
    *,
    suspicious_min_score: int,
    suspicious_max_score: int,
) -> int:
    clean_verdict = str(verdict or "").strip().lower()
    if clean_verdict == "phishing":
        return max(35, score)
    if clean_verdict == "suspicious":
        return max(suspicious_min_score, min(suspicious_max_score, score))
    return min(max(0, suspicious_min_score - 1), score)


def merge_judge_verdict(
    *,
    deterministic_score: int,
    judge_verdict: str,
    judge_confidence: float,
    suspicious_min_score: int,
    suspicious_max_score: int,
    policy: PipelinePolicy | None = None,
) -> str:
    active = (policy or PipelinePolicy()).normalized()
    low_band_promote_hi = max(
        active.judge_promote_low_to_suspicious_confidence,
        active.judge_override_mid_band_confidence,
    )
    low_band_promote_mid = min(
        active.judge_promote_low_to_suspicious_confidence,
        active.judge_override_mid_band_confidence,
    )
    base = verdict_from_score(
        deterministic_score,
        suspicious_min_score=suspicious_min_score,
        suspicious_max_score=suspicious_max_score,
    )
    clean_judge = str(judge_verdict or "").strip().lower()
    if clean_judge not in {"benign", "suspicious", "phishing"}:
        clean_judge = base

    if deterministic_score >= 35:
        return "phishing"
    if deterministic_score < suspicious_min_score and clean_judge == "phishing":
        if judge_confidence >= low_band_promote_hi:
            return "phishing"
        if judge_confidence >= low_band_promote_mid:
            return "suspicious"
        return "benign"
    if deterministic_score < suspicious_min_score:
        if clean_judge == "suspicious" and judge_confidence >= active.judge_override_mid_band_confidence:
            return "suspicious"
        # Near the suspicious band, avoid overly confident benign outcomes when the judge itself is uncertain.
        # This preserves recall on text-only cases where deterministic signals are meaningful but incomplete.
        near_suspicious_floor = max(1, suspicious_min_score - 10)
        if deterministic_score >= near_suspicious_floor and judge_confidence < active.judge_override_mid_band_confidence:
            return "suspicious"
        return "benign"
    if deterministic_score > suspicious_max_score:
        return "phishing"
    if clean_judge == "suspicious":
        return "suspicious"
    if clean_judge == "phishing" and judge_confidence >= active.judge_override_mid_band_confidence:
        return "phishing"
    if clean_judge == "benign" and judge_confidence >= active.judge_override_mid_band_confidence:
        return "benign"
    return clean_judge


def compute_confidence(*, score: int, verdict: str, judge_confidence: float, missing_count: int) -> float:
    confidence = float(judge_confidence)
    if confidence <= 0:
        confidence = max(0.0, min(1.0, round(0.35 + (score / 100.0) * 0.55, 2)))
    if missing_count > 0:
        confidence -= min(0.2, missing_count * 0.05)
    clean_verdict = str(verdict or "").strip().lower()
    if clean_verdict == "suspicious":
        confidence = min(confidence, 0.78)
    if clean_verdict == "benign" and score >= 20:
        confidence = min(confidence, 0.62)
    return max(0.0, min(1.0, round(confidence, 2)))
