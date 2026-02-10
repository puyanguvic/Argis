"""Simple routing agent."""

from __future__ import annotations

from phish_email_detection_agent.orchestrator.policy import route_text as policy_route_text

def route_text(text: str) -> str:
    return policy_route_text(text)
