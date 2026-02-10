from phish_email_detection_agent.tools.text import contains_phishing_keywords, normalize_text


def test_text_tools():
    assert normalize_text(" a   b ") == "a b"
    assert contains_phishing_keywords("urgent verify password")
