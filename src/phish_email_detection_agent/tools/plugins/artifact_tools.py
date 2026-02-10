"""Default plugin tools for URL and attachment analysis."""

from __future__ import annotations

from phish_email_detection_agent.tools.attachment_analysis import (
    AttachmentPolicy,
    analyze_attachments,
)
from phish_email_detection_agent.tools.domain_intel import analyze_domain
from phish_email_detection_agent.tools.email import extract_urls, is_suspicious_url, url_domain
from phish_email_detection_agent.tools.preprocessing import parse_input_payload
from phish_email_detection_agent.tools.url_analysis import SafeFetchPolicy, analyze_url_target


def tool_extract_urls(text: str) -> dict[str, object]:
    """Extract URLs and simple domain metadata from raw text."""

    urls = extract_urls(text)
    domains = [url_domain(item) for item in urls]
    return {"urls": urls, "domains": domains, "count": len(urls)}


def tool_analyze_urls(urls: list[str]) -> dict[str, object]:
    """Analyze URL list and flag suspicious entries."""

    clean = [item.strip() for item in (urls or []) if item and item.strip()]
    suspicious = [item for item in clean if is_suspicious_url(item)]
    return {
        "total": len(clean),
        "suspicious": suspicious,
        "suspicious_count": len(suspicious),
    }


def tool_analyze_attachments(attachments: list[str]) -> dict[str, object]:
    """Analyze attachments with file-aware and extension-aware heuristics."""

    deep = analyze_attachments(attachments, policy=AttachmentPolicy(enable_ocr=False))
    tagged = []
    for item in deep["reports"]:
        tagged.append({"name": item["name"], "risk_score": item["risk_score"], "type": item["type"]})
    return {
        "total": deep["total"],
        "tagged": tagged,
        "risky": deep["risky"],
        "risky_count": deep["risky_count"],
        "reports": deep["reports"],
        "extracted_urls": deep["extracted_urls"],
    }


def tool_parse_email(raw: str) -> dict[str, object]:
    """Parse text/json/eml payload into normalized email fields."""

    parsed = parse_input_payload(raw)
    return parsed.model_dump(mode="json")


def tool_analyze_url_targets(
    urls: list[str],
    enable_fetch: bool = False,
    sandbox_backend: str = "internal",
) -> dict[str, object]:
    """Perform safe URL target analysis with optional sandbox fetch."""

    clean = [item.strip() for item in (urls or []) if item and item.strip()]
    policy = SafeFetchPolicy(enabled=bool(enable_fetch), sandbox_backend=sandbox_backend)
    reports = [analyze_url_target(item, policy=policy) for item in clean]
    risky = [item["url"] for item in reports if int(item.get("risk_score", 0)) >= 50]
    return {"total": len(reports), "risky": risky, "reports": reports}


def tool_domain_intelligence(urls: list[str]) -> dict[str, object]:
    """Run domain-level phishing intelligence heuristics on URL list."""

    clean = [item.strip() for item in (urls or []) if item and item.strip()]
    reports = [analyze_domain(item) for item in clean]
    risky = [item["domain"] for item in reports if int(item.get("risk_score", 0)) >= 45]
    return {"total": len(reports), "risky": risky, "reports": reports}
