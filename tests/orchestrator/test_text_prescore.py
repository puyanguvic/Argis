from phish_email_detection_agent.domain.email.parse import parse_input_payload
from phish_email_detection_agent.orchestrator.pipeline import _build_nlp_cues, _compute_pre_score


def _blank_headers() -> dict[str, object]:
    return {
        "spf": {"result": ""},
        "dkim": {"result": ""},
        "dmarc": {"result": ""},
        "from_replyto_mismatch": False,
        "suspicious_received_patterns": [],
    }


def test_text_only_account_takeover_pattern_reaches_phishing_band():
    payload = """Subject: Account termination notice

Comfirm Your Account Information now.
Please contact your helpdesk immediately or your email account will be shut down.
"""
    email = parse_input_payload(payload)
    nlp = _build_nlp_cues(email)
    pre = _compute_pre_score(
        header_signals=_blank_headers(),
        url_signals=[],
        web_signals=[],
        attachment_signals=[],
        nlp_cues=nlp,
        review_threshold=30,
        deep_threshold=70,
        url_suspicious_weight=24,
    )
    assert int(pre["risk_score"]) >= 35


def test_text_only_regular_quote_stays_below_phishing_band():
    payload = """Subject: Re: Quote

Please review the attached quote and send your comments by tomorrow.
"""
    email = parse_input_payload(payload)
    nlp = _build_nlp_cues(email)
    pre = _compute_pre_score(
        header_signals=_blank_headers(),
        url_signals=[],
        web_signals=[],
        attachment_signals=[],
        nlp_cues=nlp,
        review_threshold=30,
        deep_threshold=70,
        url_suspicious_weight=24,
    )
    assert int(pre["risk_score"]) < 35
