"""Email input schema."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class AttachmentMeta(BaseModel):
    """Attachment metadata supplied with the email input."""

    filename: str
    mime: str
    size: int
    sha256: str
    flags: Optional[List[str]] = None


class EmailInput(BaseModel):
    """Normalized email input required by the detection agent."""

    raw_headers: str
    subject: str
    sender: str
    reply_to: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    attachments: List[AttachmentMeta] = Field(default_factory=list)
    received_ts: datetime

    def summary(self) -> str:
        return f"{self.subject} from {self.sender}"
