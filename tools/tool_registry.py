"""Tool registry for optional integrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable

from schemas.email_schema import EmailInput
from tools.attachment_analyzer import attachment_static_scan
from tools.content_analyzer import semantic_extract
from tools.domain_risk import domain_risk_assess
from tools.header_analyzer import header_auth_check
from tools.url_analyzer import url_chain_resolve
from tools.url_utils import extract_urls


@dataclass(frozen=True)
class Tool:
    name: str
    description: str

    def run(self, email: EmailInput) -> object:
        raise NotImplementedError


class HeadersTool(Tool):
    def __init__(self) -> None:
        super().__init__(name="header_auth", description="Check SPF/DKIM/DMARC results.")

    def run(self, email: EmailInput) -> object:
        return header_auth_check(email.raw_headers)


class UrlsTool(Tool):
    def __init__(self) -> None:
        super().__init__(name="url_chain", description="Resolve and analyze URLs.")

    def run(self, email: EmailInput) -> object:
        urls = email.urls or extract_urls([email.body_text, email.body_html])
        return url_chain_resolve(urls)


class SemanticTool(Tool):
    def __init__(self) -> None:
        super().__init__(name="semantic", description="Extract intent and urgency.")

    def run(self, email: EmailInput) -> object:
        return semantic_extract(email.subject, email.body_text, email.body_html)


class DomainRiskTool(Tool):
    def __init__(self) -> None:
        super().__init__(name="domain_risk", description="Assess lookalike domains.")

    def run(self, email: EmailInput) -> object:
        urls = email.urls or extract_urls([email.body_text, email.body_html])
        domains = [item.final_domain for item in url_chain_resolve(urls).chains if item.final_domain]
        return domain_risk_assess(domains)


class AttachmentTool(Tool):
    def __init__(self) -> None:
        super().__init__(name="attachment_scan", description="Scan attachment metadata.")

    def run(self, email: EmailInput) -> object:
        return attachment_static_scan(email.attachments)


def default_tool_registry() -> Dict[str, Tool]:
    tools = [HeadersTool(), UrlsTool(), SemanticTool(), DomainRiskTool(), AttachmentTool()]
    return {tool.name: tool for tool in tools}


def describe_tools(tools: Iterable[Tool]) -> str:
    lines = []
    for tool in tools:
        lines.append(f"- {tool.name}: {tool.description}")
    return "\n".join(lines)
