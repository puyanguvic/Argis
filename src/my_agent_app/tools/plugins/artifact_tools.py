"""Default plugin tools for URL and attachment analysis."""

from __future__ import annotations

from my_agent_app.tools.email import classify_attachment, extract_urls, is_suspicious_url, url_domain


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
    """Analyze attachment filenames and categorize risk."""

    clean = [item.strip() for item in (attachments or []) if item and item.strip()]
    tagged = [{"name": item, "risk": classify_attachment(item)} for item in clean]
    risky = [item["name"] for item in tagged if item["risk"] in {"high_risk", "macro_risk"}]
    return {"total": len(clean), "tagged": tagged, "risky": risky, "risky_count": len(risky)}
