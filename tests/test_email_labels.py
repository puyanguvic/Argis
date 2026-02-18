import json

from phish_email_detection_agent.cli import run_once


def _run_fallback(text: str, monkeypatch) -> dict[str, object]:
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    return json.loads(run_once(text, model="gpt-4.1-mini"))


def test_promotional_message_is_labeled_spam(monkeypatch):
    payload = """Subject: Weekend Deals Newsletter

Limited time offer! Buy now and get 70% discount.
Click here to claim your promo code.
To stop receiving these updates, unsubscribe at any time.
"""
    result = _run_fallback(payload, monkeypatch)
    assert result["email_label"] == "spam"
    assert result["is_spam"] is True
    assert result["is_phish_email"] is False
    assert "spam" in result["threat_tags"]
    assert "phish_email" not in result["threat_tags"]


def test_phishing_message_is_labeled_phish_email(monkeypatch):
    payload = """Subject: Action Required: Updated Invoice and Payment Verification

Dear Mick,
Please review and confirm payment information using:
https://accounts-secure-verification.com/finance/portal/invoice

This verification link remains active for 24 hours.
If no confirmation is received, the invoice may be placed on temporary hold.
"""
    result = _run_fallback(payload, monkeypatch)
    assert result["email_label"] == "phish_email"
    assert result["is_spam"] is True
    assert result["is_phish_email"] is True
    assert "spam" in result["threat_tags"]
    assert "phish_email" in result["threat_tags"]
