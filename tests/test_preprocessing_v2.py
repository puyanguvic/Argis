from phish_email_detection_agent.tools.preprocessing import parse_input_payload


def test_parse_eml_extracts_hidden_links_and_attachment():
    raw_eml = """From: attacker@example.com
To: victim@example.com
Subject: Verify Account
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="sep"

--sep
Content-Type: text/html; charset="utf-8"

<html><body>
Click <a href="https://evil-login-secure.xyz/auth">https://microsoft.com/login</a>
</body></html>
--sep
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJSVFT0Y=
--sep--
"""
    parsed = parse_input_payload(raw_eml)
    assert parsed.subject == "Verify Account"
    assert parsed.sender == "attacker@example.com"
    assert "https://evil-login-secure.xyz/auth" in parsed.urls
    assert "invoice.pdf" in parsed.attachments
    assert parsed.attachment_hashes["invoice.pdf"]


def test_parse_json_payload_merges_fields():
    payload = (
        '{"subject":"Notice","text":"See https://bit.ly/reset",'
        '"attachments":[{"name":"report.zip"}],"urls":["https://safe.example.com"]}'
    )
    parsed = parse_input_payload(payload)
    assert parsed.subject == "Notice"
    assert "https://bit.ly/reset" in parsed.urls
    assert "https://safe.example.com" in parsed.urls
    assert "report.zip" in parsed.attachments
