"""Canonical OpenAI Agents function tools."""

from __future__ import annotations

from typing import Callable

from phish_email_detection_agent.agents.router import route_text
from phish_email_detection_agent.domain.attachment.detect import classify_attachment
from phish_email_detection_agent.domain.email.parse import parse_input_payload
from phish_email_detection_agent.domain.url.extract import (
    extract_urls as extract_urls_from_text,
    is_suspicious_url,
)
from phish_email_detection_agent.tools.attachment.analyze import AttachmentPolicy, analyze_attachments
from phish_email_detection_agent.tools.intel.domain_intel import analyze_domain
from phish_email_detection_agent.tools.text.text_model import (
    contains_phishing_keywords,
    normalize_text as normalize_text_value,
)
from phish_email_detection_agent.tools.url_fetch.service import SafeFetchPolicy, analyze_url_target


ToolCallable = Callable[..., object]


def _keyword_matches(text: str) -> list[str]:
    raw = (text or "").lower()
    keywords = ("verify", "password", "urgent", "invoice", "wire transfer")
    return [item for item in keywords if item in raw]


def normalize_text(text: str) -> str:
    """Normalize spaces/newlines in email text before analysis."""

    return normalize_text_value(text)


def keyword_scan(text: str) -> dict[str, object]:
    """Scan text for common phishing keywords and return matches."""

    matches = _keyword_matches(text)
    return {
        "is_suspicious": contains_phishing_keywords(text),
        "matches": matches,
        "count": len(matches),
    }


def route_path(
    text: str,
    urls: list[str] | None = None,
    attachments: list[str] | None = None,
) -> str:
    """Return FAST/STANDARD/DEEP route from phishing-relevant signals."""

    return route_text(text, urls=urls, attachments=attachments)


def extract_urls(text: str) -> dict[str, object]:
    """Extract URLs from email or message text."""

    urls = extract_urls_from_text(text)
    return {"urls": urls, "count": len(urls)}


def check_url(url: str) -> dict[str, object]:
    """Check whether a URL looks suspicious using local heuristics."""

    return {"url": url, "suspicious": is_suspicious_url(url)}


def attachment_risk(filename: str) -> dict[str, str]:
    """Classify attachment filename risk."""

    return {"filename": filename, "risk": classify_attachment(filename)}


def parse_email(raw: str) -> dict[str, object]:
    """Parse text/json/eml input into normalized email schema."""

    return parse_input_payload(raw).model_dump(mode="json")


def url_target(
    url: str,
    enable_fetch: bool = False,
    sandbox_backend: str = "internal",
) -> dict[str, object]:
    """Analyze URL target using safe fetch and HTML signal extraction."""

    return analyze_url_target(
        url,
        policy=SafeFetchPolicy(enabled=bool(enable_fetch), sandbox_backend=sandbox_backend),
    )


def domain_intel(url: str) -> dict[str, object]:
    """Extract domain intelligence heuristics for a URL."""

    return analyze_domain(url)


def attachments_deep(attachments: list[str]) -> dict[str, object]:
    """Run deep static analysis on attachments."""

    return analyze_attachments(attachments, policy=AttachmentPolicy(enable_ocr=False))


def openai_tool_functions() -> list[ToolCallable]:
    """Return canonical function-tool callables in stable registration order."""

    return [
        normalize_text,
        keyword_scan,
        route_path,
        extract_urls,
        check_url,
        attachment_risk,
        parse_email,
        url_target,
        domain_intel,
        attachments_deep,
    ]
