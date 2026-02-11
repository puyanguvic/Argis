"""Simple routing agent."""

from __future__ import annotations

from phish_email_detection_agent.orchestrator.policy import route_text as policy_route_text


def route_text(
    text: str,
    *,
    urls: list[str] | None = None,
    attachments: list[str] | None = None,
    chain_flags: list[str] | None = None,
    hidden_link_count: int = 0,
    suspicious_url_count: int | None = None,
    risky_attachment_count: int | None = None,
) -> str:
    return policy_route_text(
        text,
        urls=urls,
        attachments=attachments,
        chain_flags=chain_flags,
        hidden_link_count=hidden_link_count,
        suspicious_url_count=suspicious_url_count,
        risky_attachment_count=risky_attachment_count,
    )
