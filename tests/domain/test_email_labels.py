def test_promotional_message_is_labeled_spam(run_fallback_once):
    payload = """Subject: Weekend Deals Newsletter

Limited time offer! Buy now and get 70% discount.
Click here to claim your promo code.
To stop receiving these updates, unsubscribe at any time.
"""
    result = run_fallback_once(payload)
    assert result["email_label"] == "spam"
    assert result["is_spam"] is True
    assert result["is_phish_email"] is False
    assert "spam" in result["threat_tags"]
    assert "phish_email" not in result["threat_tags"]


def test_phishing_message_is_labeled_phish_email(run_fallback_once):
    payload = """Subject: Action Required: Updated Invoice and Payment Verification

Dear Mick,
Please review and confirm payment information using:
https://accounts-secure-verification.com/finance/portal/invoice

This verification link remains active for 24 hours.
If no confirmation is received, the invoice may be placed on temporary hold.
"""
    result = run_fallback_once(payload)
    assert result["email_label"] == "phish_email"
    assert result["is_spam"] is True
    assert result["is_phish_email"] is True
    assert "spam" in result["threat_tags"]
    assert "phish_email" in result["threat_tags"]
