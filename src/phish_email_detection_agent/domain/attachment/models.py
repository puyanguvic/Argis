"""Attachment models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttachmentArtifact(BaseModel):
    name: str
    type: str = "unknown"
    risk_score: int = 0
    indicators: list[str] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
