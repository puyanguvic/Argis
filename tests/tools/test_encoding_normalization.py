from phish_email_detection_agent.tools.text.encoding import (
    DecodeBudget,
    analyze_url_obfuscation,
    normalize_text_layers,
    parse_data_uri,
    try_decode_base64_text,
)


def test_normalize_text_layers_decodes_html_entities_and_percent_encoding():
    raw = "Hello%20World&amp;test"
    result = normalize_text_layers(raw, budget=DecodeBudget(max_output_chars=200))
    assert result["normalized_sample"] == "Hello World&test"
    assert "html_unescape" in result["decode_steps"]
    assert "percent_decode" in result["decode_steps"]


def test_try_decode_base64_text_decodes_url_text():
    value = "aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbg=="
    report = try_decode_base64_text(value)
    assert report is not None
    assert report["status"] == "ok"
    assert "https://evil.com/login" in report["text_sample"]


def test_parse_data_uri_decodes_base64_text_payload():
    uri = "data:text/plain;base64,SGVsbG8gV29ybGQh"
    report = parse_data_uri(uri)
    assert report is not None
    assert report["status"] == "ok"
    assert report["mime"] == "text/plain"
    assert "Hello World!" in report["decoded_sample"]


def test_analyze_url_obfuscation_extracts_nested_url_from_encoded_query_value():
    url = "https://tracker.example.com/?u=https%3A%2F%2Fevil.com%2Flogin"
    analysis = analyze_url_obfuscation(url)
    assert analysis["query_param_count"] >= 1
    assert "percent_encoded_query" in analysis["flags"]
    assert "nested_url_in_query" in analysis["flags"]
    assert "https://evil.com/login" in analysis["nested_urls"]


def test_analyze_url_obfuscation_decodes_base64_query_value_into_nested_url():
    url = "https://tracker.example.com/?r=aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbg=="
    analysis = analyze_url_obfuscation(url)
    assert "base64_decoded_query_value" in analysis["flags"]
    assert "https://evil.com/login" in analysis["nested_urls"]

