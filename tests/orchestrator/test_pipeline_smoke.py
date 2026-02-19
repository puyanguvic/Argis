def test_pipeline_smoke(run_fallback_once):
    payload = run_fallback_once("hello team")
    assert payload["verdict"] in {"benign", "phishing"}


def test_fallback_collapses_suspicious_to_phishing(monkeypatch, run_fallback_once):
    monkeypatch.setenv("MY_AGENT_APP_SUSPICIOUS_MIN_SCORE", "1")
    monkeypatch.setenv("MY_AGENT_APP_SUSPICIOUS_MAX_SCORE", "34")
    payload = run_fallback_once("Subject: Help Desk Password Update")
    assert payload["provider_used"].endswith(":fallback")
    assert payload["verdict"] == "phishing"
    assert int(payload["risk_score"]) >= 35
