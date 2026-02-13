import json

from phish_email_detection_agent.cli import run_once


def test_pipeline_smoke():
    payload = json.loads(run_once("hello team"))
    assert payload["verdict"] in {"benign", "phishing"}


def test_fallback_collapses_suspicious_to_phishing(monkeypatch):
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MY_AGENT_APP_SUSPICIOUS_MIN_SCORE", "1")
    monkeypatch.setenv("MY_AGENT_APP_SUSPICIOUS_MAX_SCORE", "34")
    payload = json.loads(run_once("Subject: Help Desk Password Update", model="gpt-4.1-mini"))
    assert payload["provider_used"].endswith(":fallback")
    assert payload["verdict"] == "phishing"
    assert int(payload["risk_score"]) >= 35
