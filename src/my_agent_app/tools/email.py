"""Email artifact utility tools."""

from __future__ import annotations

from urllib.parse import urlparse
import re

URL_PATTERN = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    """Extract HTTP(S) URLs from text."""

    return list(dict.fromkeys(URL_PATTERN.findall(text or "")))


def url_domain(url: str) -> str:
    parsed = urlparse((url or "").strip())
    return (parsed.netloc or "").lower()


def is_suspicious_url(url: str) -> bool:
    raw = (url or "").lower()
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


def classify_attachment(filename: str) -> str:
    lower = (filename or "").lower().strip()
    if not lower:
        return "unknown"
    risky = (
        ".exe",
        ".msi",
        ".bat",
        ".cmd",
        ".scr",
        ".js",
        ".vbs",
        ".jar",
        ".ps1",
        ".hta",
        ".iso",
        ".zip",
        ".rar",
    )
    if any(lower.endswith(ext) for ext in risky):
        return "high_risk"
    if lower.endswith((".docm", ".xlsm", ".pptm")):
        return "macro_risk"
    return "low_risk"
