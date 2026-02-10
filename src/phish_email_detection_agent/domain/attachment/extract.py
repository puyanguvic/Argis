"""Attachment content extraction helpers."""

from __future__ import annotations

from phish_email_detection_agent.domain.url.extract import extract_urls


def extract_attachment_urls(text: str) -> list[str]:
    """Extract URLs from decoded attachment text chunks."""

    return extract_urls(text)
