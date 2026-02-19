from phish_email_detection_agent.orchestrator.evaluator import OfflineEvaluator


def test_offline_evaluator_computes_binary_metrics():
    evaluator = OfflineEvaluator()
    metrics = evaluator.evaluate_verdicts(
        predicted=["phishing", "benign", "suspicious", "benign"],
        truth=["phishing", "benign", "benign", "phishing"],
    )

    assert metrics.total == 4
    assert metrics.true_positive == 1
    assert metrics.true_negative == 1
    assert metrics.false_positive == 1
    assert metrics.false_negative == 1
    assert round(metrics.accuracy, 3) == 0.5
    assert round(metrics.precision, 3) == 0.5
    assert round(metrics.recall, 3) == 0.5
    assert round(metrics.f1, 3) == 0.5


def test_offline_evaluator_supports_record_mode():
    evaluator = OfflineEvaluator(suspicious_as_positive=False)
    metrics = evaluator.evaluate_records(
        [
            {"verdict": "suspicious", "label": "phishing"},
            {"verdict": "benign", "label": "benign"},
        ]
    )
    assert metrics.total == 2
    assert metrics.true_negative == 1
    assert metrics.false_negative == 1
