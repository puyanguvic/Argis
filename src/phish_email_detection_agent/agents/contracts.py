"""Agent-level contracts and response formats."""

from phish_email_detection_agent.domain.email.models import EmailInput
from phish_email_detection_agent.domain.evidence import (
    InvestigationReport,
    RouterDecision,
    TriageOutput,
    TriageResult,
)

__all__ = [
    "EmailInput",
    "RouterDecision",
    "InvestigationReport",
    "TriageOutput",
    "TriageResult",
]
