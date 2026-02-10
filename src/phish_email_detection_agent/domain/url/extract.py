"""URL extraction and canonicalization."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse
import re

URL_PATTERN = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    """Extract HTTP(S) URLs from text."""

    urls = URL_PATTERN.findall(text or "")
    return list(dict.fromkeys(canonicalize_url(item) for item in urls if item.strip()))


def canonicalize_url(url: str) -> str:
    """Normalize URL to a stable lowercase host form."""

    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw
    normalized = parsed._replace(netloc=parsed.netloc.lower())
    return urlunparse(normalized)


def url_domain(url: str) -> str:
    parsed = urlparse((url or "").strip())
    return (parsed.netloc or "").lower()


def is_suspicious_url(url: str) -> bool:
    raw = canonicalize_url(url).lower()
    domain = url_domain(raw)
    shorteners = ("bit.ly", "tinyurl.com", "t.co", "rb.gy")
    if any(item in domain for item in shorteners):
        return True
    if "xn--" in domain:
        return True
    if "@" in raw:
        return True
    if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", raw):
        return True
    high_risk_tokens = ("verify", "secure", "login", "account", "update", "password")
    return any(token in raw for token in high_risk_tokens)
