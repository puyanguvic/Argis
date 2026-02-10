"""Tool registry used by agent runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from phish_email_detection_agent.agents.router import route_text
from phish_email_detection_agent.domain.attachment.detect import classify_attachment
from phish_email_detection_agent.domain.email.parse import parse_input_payload
from phish_email_detection_agent.tools.attachment.analyze import AttachmentPolicy, analyze_attachments
from phish_email_detection_agent.tools.intel.domain_intel import analyze_domain
from phish_email_detection_agent.domain.url.extract import extract_urls, is_suspicious_url
from phish_email_detection_agent.tools.text.text_model import contains_phishing_keywords, normalize_text
from phish_email_detection_agent.tools.url_fetch.service import SafeFetchPolicy, analyze_url_target


def _keyword_matches(text: str) -> list[str]:
    raw = (text or "").lower()
    keywords = ("verify", "password", "urgent", "invoice", "wire transfer")
    return [item for item in keywords if item in raw]


def _tool_normalize_text(text: str) -> str:
    """Normalize spaces/newlines in user text before analysis."""

    return normalize_text(text)


def _tool_keyword_scan(text: str) -> dict[str, object]:
    """Scan text for common phishing indicators."""

    matches = _keyword_matches(text)
    return {
        "is_suspicious": contains_phishing_keywords(text),
        "matches": matches,
        "count": len(matches),
    }


def _tool_route_path(text: str) -> str:
    """Return FAST/STANDARD/DEEP route based on text length."""

    return route_text(text)


def _tool_extract_urls(text: str) -> dict[str, object]:
    """Extract URLs from message text."""

    urls = extract_urls(text)
    return {"urls": urls, "count": len(urls)}


def _tool_check_url(url: str) -> dict[str, object]:
    """Check whether a URL appears suspicious by heuristics."""

    return {"url": url, "suspicious": is_suspicious_url(url)}


def _tool_attachment_risk(filename: str) -> dict[str, str]:
    """Classify single attachment filename risk."""

    return {"filename": filename, "risk": classify_attachment(filename)}


def _tool_parse_email(raw: str) -> dict[str, object]:
    """Parse text/json/eml input into normalized email schema."""

    return parse_input_payload(raw).model_dump(mode="json")


def _tool_url_target(
    url: str,
    enable_fetch: bool = False,
    sandbox_backend: str = "internal",
) -> dict[str, object]:
    """Analyze URL target using safe fetch + HTML signal extraction."""

    return analyze_url_target(
        url,
        policy=SafeFetchPolicy(enabled=bool(enable_fetch), sandbox_backend=sandbox_backend),
    )


def _tool_domain_intel(url: str) -> dict[str, object]:
    """Extract domain intelligence heuristics for a URL."""

    return analyze_domain(url)


def _tool_attachments_deep(attachments: list[str]) -> dict[str, object]:
    """Deep attachment analysis with static-safe inspection."""

    return analyze_attachments(attachments, policy=AttachmentPolicy(enable_ocr=False))


@dataclass
class ToolRegistry:
    """Extensible registry for OpenAI Agents function tools."""

    _tools: list[object] = field(default_factory=list)

    def register_callable(self, func: Callable[..., object]) -> None:
        from agents import function_tool

        self._tools.append(function_tool(func))

    def register_default_tools(self) -> None:
        for func in (
            _tool_normalize_text,
            _tool_keyword_scan,
            _tool_route_path,
            _tool_extract_urls,
            _tool_check_url,
            _tool_attachment_risk,
            _tool_parse_email,
            _tool_url_target,
            _tool_domain_intel,
            _tool_attachments_deep,
        ):
            self.register_callable(func)

    def register_all(self) -> None:
        self.register_default_tools()

    def export(self) -> list[object]:
        return list(self._tools)
