"""URL extraction and lexical feature analysis."""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

from schemas.email_schema import EmailSchema

URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
OBFUSCATED_DOT_RE = re.compile(r"\[(?:\.)\]|\((?:\.)\)|\{(?:\.)\}")
OBFUSCATED_HTTP_RE = re.compile(r"hxxps?://", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SUSPICIOUS_DOMAIN_KEYWORDS = {"login", "verify", "secure", "account", "update"}
BRAND_KEYWORDS = {
    "microsoft",
    "office365",
    "outlook",
    "paypal",
    "google",
    "apple",
    "amazon",
    "icloud",
    "netflix",
    "dhl",
    "ups",
    "fedex",
    "bank",
}


def _extract_urls(text: str | None) -> List[str]:
    if not text:
        return []
    return URL_RE.findall(text)


def _deobfuscate(text: str) -> str:
    text = OBFUSCATED_HTTP_RE.sub("https://", text)
    text = OBFUSCATED_DOT_RE.sub(".", text)
    return text


def _clean_url(url: str) -> str:
    return url.strip(")>].,;\"'")


def _normalize_host(host: str) -> str:
    normalized = host.lower()
    normalized = (
        normalized.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("7", "t")
    )
    return normalized


def _host_from_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.split("@")[-1].split(":")[0].lower()
    return host


def analyze_urls(email: EmailSchema) -> Dict[str, object]:
    raw_body = email.body or ""
    deobfuscated_body = _deobfuscate(raw_body)
    raw_urls = email.urls or _extract_urls(raw_body)
    urls = [_clean_url(url) for url in (_extract_urls(deobfuscated_body) or raw_urls)]
    findings = []
    score = 0.0

    if urls:
        score += 0.2
    if OBFUSCATED_HTTP_RE.search(raw_body) or OBFUSCATED_DOT_RE.search(raw_body):
        findings.append("obfuscated_url")
        score += 0.2
    for url in urls:
        if "@" in url:
            findings.append("suspicious_at_symbol")
            score += 0.2
        host = _host_from_url(url)
        if not host:
            continue
        if IP_HOST_RE.match(host):
            findings.append("ip_address_url")
            score += 0.2
        if "xn--" in host:
            findings.append("punycode_domain")
            score += 0.2
        if host.count("-") >= 2:
            findings.append("excessive_hyphens")
            score += 0.1
        if any(keyword in host for keyword in SUSPICIOUS_DOMAIN_KEYWORDS):
            findings.append("suspicious_domain_keyword")
            score += 0.1
        normalized_host = _normalize_host(host)
        for brand in BRAND_KEYWORDS:
            if brand in normalized_host and brand not in host:
                findings.append("brand_lookalike")
                score += 0.3
                break

    return {"score": min(score, 1.0), "urls": urls, "findings": findings}
