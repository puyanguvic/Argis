from phish_email_detection_agent.orchestrator.pipeline import (
    _merge_judge_verdict,
    _normalize_score_for_verdict,
)


def test_high_score_does_not_fall_back_to_suspicious():
    verdict = _merge_judge_verdict(
        deterministic_score=46,
        judge_verdict="benign",
        judge_confidence=0.95,
        suspicious_min_score=24,
        suspicious_max_score=34,
    )
    assert verdict == "phishing"


def test_mid_score_allows_suspicious_when_uncertain():
    verdict = _merge_judge_verdict(
        deterministic_score=30,
        judge_verdict="suspicious",
        judge_confidence=0.4,
        suspicious_min_score=24,
        suspicious_max_score=34,
    )
    assert verdict == "suspicious"


def test_mid_score_can_be_benign_with_high_judge_confidence():
    verdict = _merge_judge_verdict(
        deterministic_score=28,
        judge_verdict="benign",
        judge_confidence=0.9,
        suspicious_min_score=24,
        suspicious_max_score=34,
    )
    assert verdict == "benign"


def test_score_is_aligned_with_benign_and_suspicious_ranges():
    benign_score = _normalize_score_for_verdict(
        27,
        "benign",
        suspicious_min_score=24,
        suspicious_max_score=34,
    )
    suspicious_score = _normalize_score_for_verdict(
        49,
        "suspicious",
        suspicious_min_score=24,
        suspicious_max_score=34,
    )
    assert benign_score <= 23
    assert 24 <= suspicious_score <= 34


def test_low_score_can_promote_to_phishing_with_high_judge_confidence():
    verdict = _merge_judge_verdict(
        deterministic_score=18,
        judge_verdict="phishing",
        judge_confidence=0.9,
        suspicious_min_score=24,
        suspicious_max_score=34,
    )
    assert verdict == "phishing"


def test_low_score_can_promote_to_suspicious_with_mid_judge_confidence():
    verdict = _merge_judge_verdict(
        deterministic_score=18,
        judge_verdict="phishing",
        judge_confidence=0.7,
        suspicious_min_score=24,
        suspicious_max_score=34,
    )
    assert verdict == "suspicious"
