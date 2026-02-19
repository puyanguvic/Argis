from phish_email_detection_agent.domain.email.parse import parse_input_payload


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


def test_parse_plaintext_subject_block_extracts_header_and_body():
    raw = """Subject: Microsoft Account Verification!!!
From: security@example.com
To: user@example.com

Please contact your helpdesk now.
Your account will be shut down unless you confirm your account information.
"""
    parsed = parse_input_payload(raw)
    assert parsed.subject == "Microsoft Account Verification!!!"
    assert parsed.sender == "security@example.com"
    assert parsed.to == ["user@example.com"]
    assert "helpdesk" in parsed.body_text.lower()
    assert "helpdesk" in parsed.text.lower()


def test_parse_subject_and_body_without_rfc_headers():
    raw = """Subject: VERIFY YOUR ACCOUNT

Your Email account has been Limited.
Confirm immediately to avoid suspension.
"""
    parsed = parse_input_payload(raw)
    assert parsed.subject == "VERIFY YOUR ACCOUNT"
    assert "limited" in parsed.body_text.lower()
    assert "verify your account" in parsed.text.lower()
