from phish_email_detection_agent.domain.url.extract import extract_urls, is_suspicious_url


def test_extract_urls_from_text():
    urls = extract_urls("please verify https://bit.ly/reset and https://example.com")
    assert "https://bit.ly/reset" in urls
    assert "https://example.com" in urls


def test_suspicious_url_heuristics():
    assert is_suspicious_url("https://bit.ly/reset") is True
    assert is_suspicious_url("https://example.com/home") is False
