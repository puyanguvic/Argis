from phish_email_detection_agent.orchestrator.policy import route_text


def test_route_text_fast_for_low_signal_message():
    assert route_text("hello team, sharing the meeting notes from yesterday.") == "FAST"


def test_route_text_short_risky_message_is_not_fast():
    result = route_text("Urgent: verify your account now at https://bit.ly/reset")
    assert result in {"STANDARD", "DEEP"}


def test_route_text_single_suspicious_url_defaults_to_standard():
    assert route_text("Please review https://bit.ly/update") == "STANDARD"


def test_route_text_risky_attachment_forces_deep():
    result = route_text(
        "Please see attachment.",
        attachments=["invoice.zip"],
        risky_attachment_count=1,
    )
    assert result == "DEEP"


def test_route_text_attack_chain_with_suspicious_url_is_deep():
    result = route_text(
        "open the statement",
        urls=["https://bit.ly/account-update"],
        attachments=["statement.pdf"],
        chain_flags=["url_to_attachment_chain", "contains_url", "contains_attachment"],
    )
    assert result == "DEEP"
