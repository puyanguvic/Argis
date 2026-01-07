"""Explanation schema for verdicts."""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class Explanation(BaseModel):
    """Structured explanation output."""

    verdict: str
    risk_score: int
    top_signals: List[str] = Field(default_factory=list)
    recommended_action: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    score_breakdown: List[Dict[str, float | str]] = Field(default_factory=list)
