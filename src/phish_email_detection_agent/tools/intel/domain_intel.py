"""Domain-level phishing intelligence heuristics."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import urlparse

COMMON_BRANDS = (
    "microsoft",
    "paypal",
    "apple",
    "google",
    "amazon",
    "bankofamerica",
    "chase",
    "dhl",
)
RISKY_TLDS = (".xyz", ".top", ".click", ".work", ".country", ".gq", ".tk")


@dataclass
class DomainIntelPolicy:
    suspicious_token_cap: int = 30
    synthetic_service_bonus: int = 18


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _base_domain(host: str) -> str:
    parts = [part for part in host.lower().split(".") if part]
    if len(parts) < 2:
        return host.lower()
    return ".".join(parts[-2:])


def _detect_typosquat(host: str) -> list[str]:
    base = _base_domain(host).split(".")[0]
    hits: list[str] = []
    for brand in COMMON_BRANDS:
        distance = _levenshtein(base, brand)
        if distance == 1:
            hits.append(brand)
            continue
        if base.startswith(brand) and len(base) - len(brand) <= 8:
            suffix = base[len(brand) :]
            if suffix and re.fullmatch(r"[-_a-z0-9]+", suffix):
                hits.append(brand)
    return list(dict.fromkeys(hits))


def analyze_domain(url: str, *, policy: DomainIntelPolicy | None = None) -> dict[str, Any]:
    active = policy or DomainIntelPolicy()
    parsed = urlparse((url or "").strip())
    host = (parsed.hostname or "").lower()
    if not host:
        return {"url": url, "domain": "", "risk_score": 0}

    risk = 0
    indicators: list[str] = []
    if "xn--" in host:
        risk += 35
        indicators.append("punycode_domain")
    if any(host.endswith(tld) for tld in RISKY_TLDS):
        risk += 20
        indicators.append("risky_tld")
    if re.search(r"\d{4,}", host):
        risk += 8
        indicators.append("numeric_domain_pattern")
    if host.count("-") >= 2:
        risk += 10
        indicators.append("excessive_hyphenation")

    typosquat = _detect_typosquat(host)
    if typosquat:
        risk += 30
        indicators.append("brand_typosquat")

    suspicious_tokens = [
        token
        for token in (
            "secure",
            "verify",
            "login",
            "update",
            "account",
            "wallet",
            "payment",
            "billing",
            "invoice",
            "finance",
            "portal",
            "support",
        )
        if token in host
    ]
    if suspicious_tokens:
        risk += min(max(0, int(active.suspicious_token_cap)), len(suspicious_tokens) * 6)
        indicators.append("credential_theme_domain")
    # Synthetic service domains often string multiple trust-themed words with hyphens.
    if host.count("-") >= 2 and len(suspicious_tokens) >= 2 and len(host) >= 20:
        risk += max(0, int(active.synthetic_service_bonus))
        indicators.append("synthetic_service_domain")

    return {
        "url": url,
        "domain": host,
        "base_domain": _base_domain(host),
        "typosquat_brands": typosquat,
        "suspicious_tokens": suspicious_tokens,
        "indicators": indicators,
        "risk_score": min(100, risk),
    }
