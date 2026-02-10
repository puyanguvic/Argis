"""Email domain models."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class EmailInput(BaseModel):
    """Normalized email input supporting text, URLs, and attachments."""

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
