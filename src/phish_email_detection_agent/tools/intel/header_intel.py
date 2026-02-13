"""Header-level phishing signals (SPF/DKIM/DMARC and relay path)."""

from __future__ import annotations

import re
from typing import Any


_AUTH_RESULT_PATTERN = re.compile(r"\b(?P<key>spf|dkim|dmarc)\s*=\s*(?P<value>[a-zA-Z_]+)")
_EMAIL_DOMAIN_PATTERN = re.compile(r"@([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)
_PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[0-1])\.)"
)


def _extract_domain(raw: str) -> str:
    if not raw:
        return ""
    match = _EMAIL_DOMAIN_PATTERN.search(raw.lower())
    if match:
        return match.group(1)
    return ""


def _parse_auth_results(headers: dict[str, str]) -> dict[str, dict[str, str]]:
    auth = {
        "spf": {"result": "none", "domain": "", "policy": ""},
        "dkim": {"result": "none", "domain": "", "policy": ""},
        "dmarc": {"result": "none", "domain": "", "policy": ""},
    }
    source = " ".join(
        str(headers.get(key, ""))
        for key in ("authentication-results", "received-spf", "arc-authentication-results")
    )
    lowered = source.lower()
    for match in _AUTH_RESULT_PATTERN.finditer(lowered):
        key = match.group("key")
        value = match.group("value")
        auth[key]["result"] = value

    spf_mail_from = re.search(r"\bsmtp\.mailfrom=([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})", lowered)
    if spf_mail_from:
        auth["spf"]["domain"] = _extract_domain(spf_mail_from.group(1))
    dkim_domain = re.search(r"\bd=([a-z0-9.-]+\.[a-z]{2,})", lowered)
    if dkim_domain:
        auth["dkim"]["domain"] = dkim_domain.group(1)
    dmarc_policy = re.search(r"\bp=([a-z]+)\b", lowered)
    if dmarc_policy:
        auth["dmarc"]["policy"] = dmarc_policy.group(1)
    return auth


def _received_lines(headers_raw: str) -> list[str]:
    return [line.strip() for line in (headers_raw or "").splitlines() if line.lower().startswith("received:")]


def analyze_headers(
    *,
    headers: dict[str, str] | None = None,
    headers_raw: str = "",
    sender: str = "",
    reply_to: str = "",
) -> dict[str, Any]:
    header_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    auth = _parse_auth_results(header_map)
    received_lines = _received_lines(headers_raw)
    suspicious_received: list[str] = []
    has_header_context = bool((headers_raw or "").strip()) or bool(header_map)
    if has_header_context and not received_lines:
        suspicious_received.append("missing_received_headers")
    if len(received_lines) >= 9:
        suspicious_received.append("unusually_long_received_chain")
    if any(_PRIVATE_IP_PATTERN.search(line) for line in received_lines):
        suspicious_received.append("private_ip_in_received_chain")
    if any("localhost" in line.lower() for line in received_lines):
        suspicious_received.append("localhost_received_hop")

    sender_domain = _extract_domain(sender)
    reply_to_domain = _extract_domain(reply_to)
    mismatch = bool(sender_domain and reply_to_domain and sender_domain != reply_to_domain)

    positive_auth = sum(
        1 for key in ("spf", "dkim", "dmarc") if auth[key]["result"] in {"pass", "bestguesspass"}
    )
    negative_auth = sum(1 for key in ("spf", "dkim", "dmarc") if auth[key]["result"] in {"fail", "softfail"})
    confidence = 0.35 + 0.15 * positive_auth + 0.1 * negative_auth
    confidence = min(1.0, max(0.0, confidence))

    return {
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "from_replyto_mismatch": mismatch,
        "received_hops": len(received_lines),
        "suspicious_received_patterns": suspicious_received,
        "confidence": confidence,
    }
