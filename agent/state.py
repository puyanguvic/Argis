"""Detection result state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from schemas.email_schema import EmailInput
from schemas.evidence_schema import EvidenceStore
from schemas.explanation_schema import Explanation


@dataclass
class DetectionResult:
    email: Optional[EmailInput]
    evidence: EvidenceStore
    verdict: str
    risk_score: int
    explanation: Explanation
    trace_id: str
    runtime_ms: int
