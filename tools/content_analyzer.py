"""Semantic extraction for intent and urgency (deterministic)."""

from __future__ import annotations

from typing import Iterable

from schemas.evidence_schema import SemanticResult

_BRANDS = {
    "microsoft",
    "paypal",
    "google",
    "apple",
    "amazon",
    "bank",
    "dhl",
    "ups",
    "fedex",
}
_INTENT_KEYWORDS = {
    "credential_theft": {"password", "login", "verify account", "update account", "signin"},
    "invoice_payment": {"invoice", "payment", "wire transfer", "bank transfer", "remit"},
    "oauth_consent": {"consent", "oauth", "authorize", "grant access"},
    "malware_delivery": {"install", "enable content", "macro", "download attachment"},
}
_URGENCY_HIGH = {"immediately", "urgent", "act now", "within 24 hours", "limited time"}
_URGENCY_MEDIUM = {"soon", "asap", "within 48 hours", "today"}
_REQUESTED_ACTIONS = {
    "click": {"click", "open", "visit"},
    "download": {"download", "open attachment", "install"},
    "reply": {"reply", "respond"},
    "call": {"call", "phone"},
}


def _combine_texts(subject: str, body_text: str | None, body_html: str | None) -> str:
    parts = [subject or ""]
    if body_text:
        parts.append(body_text)
    if body_html:
        parts.append(body_html)
    return "\n".join(parts).lower()


def _detect_intent(text: str) -> tuple[str, float]:
    for intent, keywords in _INTENT_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return intent, 0.8
    return "benign", 0.4


def _detect_urgency(text: str) -> int:
    if any(keyword in text for keyword in _URGENCY_HIGH):
        return 3
    if any(keyword in text for keyword in _URGENCY_MEDIUM):
        return 2
    return 0


def _detect_brands(text: str) -> list[str]:
    brands = [brand for brand in _BRANDS if brand in text]
    return brands


def _detect_actions(text: str) -> list[str]:
    actions: list[str] = []
    for action, keywords in _REQUESTED_ACTIONS.items():
        if any(keyword in text for keyword in keywords):
            actions.append(action)
    return actions


def semantic_extract(subject: str, body_text: str | None, body_html: str | None) -> SemanticResult:
    """Extract intent, urgency, and entities from email content."""

    text = _combine_texts(subject, body_text, body_html)
    intent, confidence = _detect_intent(text)
    urgency = _detect_urgency(text)
    brands = _detect_brands(text)
    actions = _detect_actions(text)
    if intent != "benign" and urgency == 0:
        urgency = 1

    return SemanticResult(
        intent=intent,
        urgency=urgency,
        brand_entities=brands,
        requested_actions=actions,
        confidence=confidence,
    )
