"""Text tools."""

from __future__ import annotations

import re
from typing import Any


_SPAM_PROMO_TOKENS = (
    "unsubscribe",
    "newsletter",
    "limited time offer",
    "special offer",
    "buy now",
    "free trial",
    "winner",
    "congratulations",
    "promo code",
    "discount",
    "sale",
    "earn money",
    "work from home",
    "crypto giveaway",
)
_SPAM_ACTION_PATTERNS = (
    re.compile(r"\bclick here\b"),
    re.compile(r"\bshop now\b"),
    re.compile(r"\bclaim (?:your )?(?:offer|reward|prize)\b"),
    re.compile(r"\bsubscribe\b"),
)


def normalize_text(value: str) -> str:
    return " ".join((value or "").split()).strip()


def contains_phishing_keywords(value: str) -> bool:
    text = (value or "").lower()
    return any(k in text for k in ("verify", "password", "urgent", "invoice", "wire transfer"))


def _spam_signal_score(
    *,
    subject: str,
    text: str,
    urls: list[str] | None = None,
) -> int:
    lowered = f"{subject}\n{text}".lower()
    score = sum(1 for token in _SPAM_PROMO_TOKENS if token in lowered)
    score += sum(1 for pattern in _SPAM_ACTION_PATTERNS if pattern.search(lowered))
    if lowered.count("!") >= 3:
        score += 1
    if len(urls or []) >= 2:
        score += 1
    return max(0, min(10, int(score)))


def derive_email_labels(
    *,
    verdict: str,
    risk_score: int,
    subject: str = "",
    text: str = "",
    urls: list[str] | None = None,
) -> dict[str, Any]:
    clean_verdict = str(verdict or "").strip().lower()
    bounded_score = max(0, min(100, int(risk_score)))
    is_phish_email = clean_verdict == "phishing" or bounded_score >= 35
    spam_score = _spam_signal_score(subject=subject, text=text, urls=urls)
    is_spam = is_phish_email or spam_score >= 2

    if is_phish_email:
        email_label = "phish_email"
    elif is_spam:
        email_label = "spam"
    else:
        email_label = "benign"

    threat_tags: list[str] = []
    if is_spam:
        threat_tags.append("spam")
    if is_phish_email:
        threat_tags.append("phish_email")

    return {
        "email_label": email_label,
        "is_spam": bool(is_spam),
        "is_phish_email": bool(is_phish_email),
        "spam_score": spam_score,
        "threat_tags": threat_tags,
    }
