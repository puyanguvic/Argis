"""Basic content safety checks for demo usage."""

from __future__ import annotations


_BLOCKED_PATTERNS = ("api_key", "private_key", "password=")


def contains_sensitive_hint(value: str) -> bool:
    text = (value or "").lower()
    return any(pattern in text for pattern in _BLOCKED_PATTERNS)
