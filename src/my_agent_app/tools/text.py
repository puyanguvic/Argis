"""Text tools."""

from __future__ import annotations


def normalize_text(value: str) -> str:
    return " ".join((value or "").split()).strip()


def contains_phishing_keywords(value: str) -> bool:
    text = (value or "").lower()
    return any(k in text for k in ("verify", "password", "urgent", "invoice", "wire transfer"))
