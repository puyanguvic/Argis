from __future__ import annotations

from datetime import datetime, timezone

from agent.orchestrator import AgentOrchestrator
from agent.report import build_report
from schemas.email_schema import EmailInput


def _base_email(**overrides) -> EmailInput:
    data = {
        "raw_headers": "spf=pass dkim=pass dmarc=pass",
        "subject": "SharePoint access review required",
        "sender": "collab-alerts@external-example.com",
        "reply_to": None,
        "body_text": "Please review access and confirm permissions for the shared folder.",
        "body_html": None,
        "urls": [],
        "attachments": [],
        "received_ts": datetime.now(timezone.utc),
    }
    data.update(overrides)
    return EmailInput(**data)


def test_contextual_escalation_routes_to_standard() -> None:
    orchestrator = AgentOrchestrator()
    result = orchestrator.detect(_base_email())

    assert result.evidence.path == "STANDARD"
    assert "profile_escalated_contextual_signal" in result.evidence.degradations


def test_contextual_escalation_report_not_allow_zero() -> None:
    orchestrator = AgentOrchestrator()
    result = orchestrator.detect(_base_email())

    assert result.risk_score > 0
    report = build_report(result)
    assert "Limited evidence collected in this profile" in report
    assert "No significant risk signals detected." not in report
    assert "Thought:" not in report
