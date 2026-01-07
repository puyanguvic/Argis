"""URL chain resolution and lexical analysis (deterministic)."""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlparse

import tldextract

from schemas.evidence_schema import UrlChainHop, UrlChainItem, UrlChainResult

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_SUSPICIOUS_TLDS = {"zip", "mov", "click", "xyz", "top", "quest", "gq"}
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
_LOGIN_KEYWORDS = {"login", "signin", "verify", "account", "password", "secure"}
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.split("@")[-1].split(":")[0].lower()
    if not host:
        return ""
    extracted = _EXTRACT(host)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def _has_ip_host(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.netloc.split("@")[-1].split(":")[0]
    return bool(_IP_RE.match(host))


def _suspicious_tld(domain: str) -> bool:
    parts = domain.rsplit(".", 1)
    if len(parts) < 2:
        return False
    return parts[-1] in _SUSPICIOUS_TLDS


def _contains_login_keywords(url: str) -> bool:
    lowered = url.lower()
    return any(keyword in lowered for keyword in _LOGIN_KEYWORDS)


def url_chain_resolve(urls: Iterable[str]) -> UrlChainResult:
    """Resolve URL chains deterministically without network access."""

    chains: list[UrlChainItem] = []
    errors: list[str] = []

    for raw_url in urls:
        url = (raw_url or "").strip()
        if not url:
            continue
        try:
            final_url = url
            final_domain = _domain_from_url(final_url)
            has_ip = _has_ip_host(final_url)
            chains.append(
                UrlChainItem(
                    input=url,
                    hops=[UrlChainHop(url=url)],
                    final_url=final_url,
                    final_domain=final_domain,
                    has_ip=has_ip,
                    suspicious_tld=_suspicious_tld(final_domain),
                    shortener=final_domain in _SHORTENERS,
                    contains_login_keywords=_contains_login_keywords(final_url),
                )
            )
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"failed:{url}:{exc}")

    return UrlChainResult(chains=chains, errors=errors)
