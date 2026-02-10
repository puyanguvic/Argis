from phish_email_detection_agent.agents.service import AgentService


def test_fallback_deep_detection_with_url_and_attachment():
    svc = AgentService(provider="openai", model="gpt-4.1-mini")
    payload = svc.analyze(
        '{"text":"Urgent: verify your password now at https://bit.ly/reset",'
        '"attachments":["invoice.zip"],"urls":["https://bit.ly/reset"]}'
    )
    assert payload["risk_score"] >= 35
    assert payload["verdict"] == "phishing"
    assert any(item.startswith("url:") for item in payload["indicators"])
    assert any(item.startswith("attachment:") for item in payload["indicators"])
