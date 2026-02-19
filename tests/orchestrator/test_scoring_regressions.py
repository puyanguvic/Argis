def test_finance_urgency_with_synthetic_domain_is_phishing(run_fallback_once):
    payload = """Subject: Action Required: Updated Invoice and Payment Verification

Dear Mick,

As part of our routine quarterly reconciliation, we identified a discrepancy in the payment
status for Invoice #INV-84721. Please review and confirm payment information using:
https://accounts-secure-verification.com/finance/portal/invoice

For security reasons, this verification link remains active for 24 hours.
If no confirmation is received, the invoice may be placed on temporary hold.
"""
    result = run_fallback_once(payload)
    assert result["verdict"] == "phishing"
    assert int(result["risk_score"]) >= 35


def test_regular_invoice_notice_on_normal_domain_stays_benign(run_fallback_once):
    payload = """Subject: January invoice reminder

Hi team,
Please review invoice INV-84721 in the vendor portal:
https://portal.acme.com/invoices/INV-84721
Thanks.
"""
    result = run_fallback_once(payload)
    assert result["verdict"] == "benign"
    assert int(result["risk_score"]) < 35
