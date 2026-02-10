"""Structured contracts for agent I/O."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class EmailInput(BaseModel):
    """Normalized email input supporting text, URLs and attachments."""

    text: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    sender: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    urls: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)
    attachment_hashes: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _fill_text_from_body(self) -> "EmailInput":
        if not self.text:
            if self.body_text:
                self.text = self.body_text
            elif self.body_html:
                self.text = self.body_html
        return self


class RouterDecision(BaseModel):
    """Decision produced by routing agent."""

    path: Literal["FAST", "STANDARD", "DEEP"]
    needs_deep: bool
    rationale: str = Field(min_length=2)


class InvestigationReport(BaseModel):
    """Detailed artifact-level investigation output."""

    suspicious_urls: list[str] = Field(default_factory=list)
    risky_attachments: list[str] = Field(default_factory=list)
    keyword_hits: list[str] = Field(default_factory=list)
    chain_signals: list[str] = Field(default_factory=list)
    artifact_reports: dict[str, object] = Field(default_factory=dict)
    risk_score: int = Field(ge=0, le=100, default=0)
    summary: str = Field(min_length=2)


class TriageOutput(BaseModel):
    """Strict output expected from final summarizer agent."""

    verdict: Literal["phishing", "benign"]
    reason: str = Field(min_length=2)
    path: Literal["FAST", "STANDARD", "DEEP"]
    risk_score: int = Field(ge=0, le=100)
    indicators: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    """Application-level result returned to callers."""

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
