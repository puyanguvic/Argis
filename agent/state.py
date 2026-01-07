"""Agent state container."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from schemas.email_schema import EmailSchema


@dataclass
class AgentState:
    email: EmailSchema
    evidence: Dict[str, Any]
    scores: Dict[str, float]
    risk: float
    label: str
