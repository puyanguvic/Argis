from phish_email_detection_agent.tools.intel.header_intel import analyze_headers


def test_header_intel_extracts_auth_and_mismatch():
    headers = {
        "authentication-results": (
            "mx.example; spf=pass smtp.mailfrom=alerts@bank.com; "
            "dkim=pass header.d=bank.com; dmarc=fail (p=reject)"
        )
    }
    raw = (
        "Received: from mail.bank.com (203.0.113.8)\n"
        "Received: from localhost (127.0.0.1)\n"
    )
    out = analyze_headers(
        headers=headers,
        headers_raw=raw,
        sender="alerts@bank.com",
        reply_to="security@bank-support.xyz",
    )
    assert out["spf"]["result"] == "pass"
    assert out["dkim"]["result"] == "pass"
    assert out["dmarc"]["result"] == "fail"
    assert out["from_replyto_mismatch"] is True
    assert out["received_hops"] == 2
    assert "private_ip_in_received_chain" in out["suspicious_received_patterns"]


def test_header_intel_plain_text_input_does_not_force_missing_received_flag():
    out = analyze_headers(headers={}, headers_raw="", sender="", reply_to="")
    assert "missing_received_headers" not in out["suspicious_received_patterns"]
