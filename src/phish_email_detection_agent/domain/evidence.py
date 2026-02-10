"""Unified evidence/report structures."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RouterDecision(BaseModel):
    path: Literal["FAST", "STANDARD", "DEEP"]
    needs_deep: bool
    rationale: str = Field(min_length=2)


class InvestigationReport(BaseModel):
    suspicious_urls: list[str] = Field(default_factory=list)
    risky_attachments: list[str] = Field(default_factory=list)
    keyword_hits: list[str] = Field(default_factory=list)
    chain_signals: list[str] = Field(default_factory=list)
    artifact_reports: dict[str, object] = Field(default_factory=dict)
    risk_score: int = Field(ge=0, le=100, default=0)
    summary: str = Field(min_length=2)


class TriageOutput(BaseModel):
    verdict: Literal["phishing", "benign"]
    reason: str = Field(min_length=2)
    path: Literal["FAST", "STANDARD", "DEEP"]
    risk_score: int = Field(ge=0, le=100)
    indicators: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    verdict: Literal["phishing", "benign"]
    reason: str
    path: Literal["FAST", "STANDARD", "DEEP"]
    risk_score: int = Field(ge=0, le=100)
    indicators: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    input: str
    urls: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)
    provider_used: str
    evidence: dict[str, object] = Field(default_factory=dict)
