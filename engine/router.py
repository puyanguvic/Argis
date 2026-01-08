"""Planner/router for detection paths."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Iterable

from engine.config import RouterConfig
from schemas.email_schema import EmailInput
from schemas.evidence_schema import EvidenceStore, PlanSpec, QuickFeatures
from tools_builtin.header_analyzer import header_auth_check
from tools_builtin.url_utils import extract_urls

_SUBJECT_SUSPICIOUS = {"urgent", "verify", "password", "invoice", "payment", "action required"}
_DOMAIN_RE = re.compile(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)


def _domain_from_address(address: str) -> str:
    _, email_addr = parseaddr(address or "")
    if "@" not in email_addr:
        return ""
    return email_addr.split("@", 1)[-1].lower()


def _domains_from_text(text: str) -> list[str]:
    return [match.lower() for match in _DOMAIN_RE.findall(text or "")]


def quick_features(email: EmailInput) -> QuickFeatures:
    """Compute router features from the input email."""

    sender_domain = _domain_from_address(email.sender)
    reply_domain = _domain_from_address(email.reply_to or "")
    sender_domains_in_text = _domains_from_text(email.sender)
    from_domain_mismatch = False
    for domain in sender_domains_in_text:
        if sender_domain and domain != sender_domain:
            from_domain_mismatch = True
            break

    urls = email.urls or extract_urls([email.body_text, email.body_html])
    subject = (email.subject or "").lower()
    suspicious_subject = any(phrase in subject for phrase in _SUBJECT_SUSPICIOUS)

    return QuickFeatures(
        from_domain_mismatch=from_domain_mismatch,
        reply_to_mismatch=bool(reply_domain and sender_domain and reply_domain != sender_domain),
        has_urls=bool(urls),
        suspicious_subject=suspicious_subject,
    )


def preliminary_score(features: QuickFeatures, header) -> float:
    """Score fast deterministic signals into a 0-100 range."""

    score = 0.0
    if features.from_domain_mismatch:
        score += 20.0
    if features.reply_to_mismatch:
        score += 20.0
    if features.has_urls:
        score += 10.0
    if features.suspicious_subject:
        score += 15.0
    if header:
        if header.spf == "fail":
            score += 20.0
        if header.dmarc == "fail":
            score += 15.0
        if header.dkim == "fail":
            score += 10.0
        if not header.aligned:
            score += 10.0
    return min(score, 100.0)


def choose_path(
    evidence: EvidenceStore,
    config: RouterConfig,
) -> str:
    """Choose FAST, STANDARD, or DEEP based on preliminary score."""

    prelim = evidence.preliminary_score or 0.0
    if prelim < config.t_fast:
        return "FAST"
    if prelim >= config.t_deep:
        return "DEEP"
    return "STANDARD"


def _tools_for_path(path: str, config: RouterConfig) -> tuple[str, ...]:
    if path == "FAST":
        return config.fast_tools
    if path == "DEEP":
        return config.deep_tools
    return config.standard_tools


def plan_routes(email: EmailInput, config: RouterConfig) -> EvidenceStore:
    """Populate evidence with router signals and structured plan."""

    evidence = EvidenceStore()
    header = header_auth_check(email.raw_headers)
    features = quick_features(email)
    evidence.header_auth = header
    evidence.quick_features = features
    evidence.preliminary_score = preliminary_score(features, header)
    path = choose_path(evidence, config)
    evidence.path = path
    evidence.plan = PlanSpec(
        path=path,
        tools=list(_tools_for_path(path, config)),
        budget_ms=config.budget_ms,
        timeout_s=config.timeout_s,
        fallback=config.fallback,
    )
    return evidence
