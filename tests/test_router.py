from __future__ import annotations

from datetime import datetime, timezone

from agent.config import RouterConfig
from agent.router import plan_routes
from schemas.email_schema import EmailInput


def _base_email(**overrides) -> EmailInput:
    data = {
        "raw_headers": "spf=pass dkim=pass dmarc=pass",
        "subject": "Hello there",
        "sender": "alice@example.com",
        "reply_to": None,
        "body_text": "Just checking in.",
        "body_html": None,
        "urls": [],
        "attachments": [],
        "received_ts": datetime.now(timezone.utc),
    }
    data.update(overrides)
    return EmailInput(**data)


def test_router_fast_path() -> None:
    email = _base_email()
    evidence = plan_routes(email, RouterConfig(t_fast=20, t_deep=60))
    assert evidence.path == "FAST"
    assert evidence.plan
    assert "header_auth_check" in evidence.plan.tools


def test_router_standard_path() -> None:
    email = _base_email(subject="Urgent verify your account", urls=["https://example.com"])
    evidence = plan_routes(email, RouterConfig(t_fast=20, t_deep=60))
    assert evidence.path == "STANDARD"
    assert evidence.plan
    assert "url_chain_resolve" in evidence.plan.tools


def test_router_deep_path() -> None:
    email = _base_email(
        raw_headers="spf=fail dkim=fail dmarc=fail",
        subject="Urgent payment required",
        reply_to="billing@evil.com",
    )
    evidence = plan_routes(email, RouterConfig(t_fast=20, t_deep=60))
    assert evidence.path == "DEEP"
    assert evidence.plan
    assert "domain_risk_assess" in evidence.plan.tools
