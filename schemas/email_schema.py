"""Unified email schema."""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class EmailSchema(BaseModel):
    subject: Optional[str] = None
    sender: Optional[str] = None
    to: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)
    body: Optional[str] = None
    raw_headers: Dict[str, str] = Field(default_factory=dict)
    urls: List[str] = Field(default_factory=list)
    attachments: List[str] = Field(default_factory=list)

    def summary(self) -> str:
        subject = self.subject or "(no subject)"
        sender = self.sender or "(unknown sender)"
        return f"{subject} from {sender}"
