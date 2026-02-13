"""Privacy and token-safe redaction for evidence payloads."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


_EMAIL_RE = re.compile(r"\b([a-z0-9._%+-]{1,64})@([a-z0-9.-]+\.[a-z]{2,})\b", re.IGNORECASE)
_TOKEN_KEYS = {
    "token",
    "code",
    "auth",
    "authorization",
    "session",
    "key",
    "apikey",
    "access_token",
    "id_token",
    "refresh_token",
    "cookie",
    "sig",
    "signature",
}


def _mask_email(text: str) -> str:
    return _EMAIL_RE.sub(lambda m: f"{m.group(1)[:2]}***@{m.group(2)}", text)


def _short_hash(raw: str) -> str:
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    return digest[:12]


def _redact_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return _mask_email(url)
    sanitized_pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in _TOKEN_KEYS or len(value) > 24:
            sanitized_pairs.append((key, f"<redacted:{_short_hash(value)}>" if value else "<redacted>"))
        else:
            sanitized_pairs.append((key, value))
    redacted_query = urlencode(sanitized_pairs, doseq=True)
    clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, redacted_query, ""))
    return _mask_email(clean)


def _redact_text(value: str) -> str:
    text = _mask_email(value)
    # Mask obvious bearer-like token segments.
    text = re.sub(r"\b[A-Za-z0-9_-]{30,}\b", "<redacted-token>", text)
    return text


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): redact_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            return _redact_url(value)
        return _redact_text(value)
    return value
