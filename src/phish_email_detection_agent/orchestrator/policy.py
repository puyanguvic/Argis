"""Budget-aware routing and early-exit policy."""

from __future__ import annotations

import re

from phish_email_detection_agent.domain.url.extract import extract_urls, is_suspicious_url

_PHISHING_TOKENS = (
    "verify",
    "password",
    "urgent",
    "invoice",
    "wire transfer",
    "login",
    "security alert",
    "account locked",
    "suspended",
    "mfa",
    "gift card",
)
_URGENCY_TOKENS = (
    "urgent",
    "immediately",
    "asap",
    "expires",
    "within 24 hours",
    "final notice",
    "action required",
    "suspended",
)
_ACTION_PATTERNS = (
    re.compile(r"\bverify (?:your )?(?:account|identity|credentials)\b"),
    re.compile(r"\breset (?:your )?password\b"),
    re.compile(r"\b(?:click|open|download)\b"),
    re.compile(r"\blog(?:-| )?in\b"),
)


def _count_token_hits(text: str, tokens: tuple[str, ...]) -> int:
    return sum(1 for token in tokens if token in text)


def _count_action_hits(text: str) -> int:
    return sum(1 for pattern in _ACTION_PATTERNS if pattern.search(text))


class PipelinePolicy:
    """Signal-based policy object for route selection and early exits."""

    def route_text(
        self,
        text: str,
        *,
        urls: list[str] | None = None,
        attachments: list[str] | None = None,
        chain_flags: list[str] | None = None,
        hidden_link_count: int = 0,
        suspicious_url_count: int | None = None,
        risky_attachment_count: int | None = None,
    ) -> str:
        raw_text = text or ""
        lowered = raw_text.lower()

        collected_urls = list(dict.fromkeys((urls or []) + extract_urls(raw_text)))
        attachment_count = len(attachments or [])
        chain_flag_set = {item for item in (chain_flags or []) if isinstance(item, str)}

        computed_suspicious_urls = sum(1 for item in collected_urls if is_suspicious_url(item))
        suspicious_count = (
            max(0, int(suspicious_url_count))
            if suspicious_url_count is not None
            else computed_suspicious_urls
        )
        risky_attachment_hits = max(0, int(risky_attachment_count or 0))
        hidden_links = max(0, int(hidden_link_count))

        phishing_hits = _count_token_hits(lowered, _PHISHING_TOKENS)
        urgency_hits = _count_token_hits(lowered, _URGENCY_TOKENS)
        action_hits = _count_action_hits(lowered)
        chain_hits = sum(
            1
            for item in (
                "url_to_attachment_chain",
                "nested_url_in_attachment",
                "hidden_html_links",
                "contains_attachment",
            )
            if item in chain_flag_set
        )

        score = 0
        score += min(4, phishing_hits)
        score += min(3, urgency_hits)
        score += min(3, action_hits)
        score += min(4, suspicious_count * 2)
        score += 2 if len(collected_urls) >= 3 else 0
        score += 2 if hidden_links > 0 else 0
        score += min(3, chain_hits)
        score += 1 if attachment_count > 0 else 0
        score += min(3, risky_attachment_hits * 2)

        attack_chain_present = (
            "url_to_attachment_chain" in chain_flag_set
            or "nested_url_in_attachment" in chain_flag_set
            or ("contains_url" in chain_flag_set and "contains_attachment" in chain_flag_set)
        )
        if risky_attachment_hits > 0:
            return "DEEP"
        if hidden_links > 0 and suspicious_count > 0:
            return "DEEP"
        if suspicious_count >= 2:
            return "DEEP"
        if attack_chain_present and suspicious_count > 0:
            return "DEEP"
        if score >= 8:
            return "DEEP"
        if score >= 3 or suspicious_count > 0 or attachment_count > 0 or len(collected_urls) >= 2:
            return "STANDARD"
        return "FAST"

    def should_early_exit(self, *, has_content: bool) -> bool:
        return not has_content


def route_text(
    text: str,
    *,
    urls: list[str] | None = None,
    attachments: list[str] | None = None,
    chain_flags: list[str] | None = None,
    hidden_link_count: int = 0,
    suspicious_url_count: int | None = None,
    risky_attachment_count: int | None = None,
) -> str:
    return PipelinePolicy().route_text(
        text,
        urls=urls,
        attachments=attachments,
        chain_flags=chain_flags,
        hidden_link_count=hidden_link_count,
        suspicious_url_count=suspicious_url_count,
        risky_attachment_count=risky_attachment_count,
    )
