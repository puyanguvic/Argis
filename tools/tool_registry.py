"""Tool registry and classes for the agent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable

from agent.config import LLMConfig
from schemas.email_schema import EmailSchema
from tools.attachment_analyzer import analyze_attachments
from tools.content_analyzer import analyze_content
from tools.header_analyzer import analyze_headers
from tools.url_analyzer import analyze_urls


@dataclass(frozen=True)
class Tool:
    name: str
    description: str

    def run(self, email: EmailSchema, llm_config: LLMConfig | None = None) -> Dict[str, object]:
        raise NotImplementedError


class HeadersTool(Tool):
    def __init__(self) -> None:
        super().__init__(
            name="headers",
            description="Check sender/subject and header mismatches.",
        )

    def run(self, email: EmailSchema, llm_config: LLMConfig | None = None) -> Dict[str, object]:
        return analyze_headers(email)


class UrlsTool(Tool):
    def __init__(self) -> None:
        super().__init__(
            name="urls",
            description="Analyze links for obfuscation, lookalikes, and risky patterns.",
        )

    def run(self, email: EmailSchema, llm_config: LLMConfig | None = None) -> Dict[str, object]:
        return analyze_urls(email)


class ContentTool(Tool):
    def __init__(self) -> None:
        super().__init__(
            name="content",
            description="Scan text for phishing language and pressure tactics.",
        )

    def run(self, email: EmailSchema, llm_config: LLMConfig | None = None) -> Dict[str, object]:
        return analyze_content(email, llm_config=llm_config)


class AttachmentsTool(Tool):
    def __init__(self) -> None:
        super().__init__(
            name="attachments",
            description="Inspect attachment names for suspicious extensions.",
        )

    def run(self, email: EmailSchema, llm_config: LLMConfig | None = None) -> Dict[str, object]:
        return analyze_attachments(email)


def default_tool_registry() -> Dict[str, Tool]:
    tools = [HeadersTool(), UrlsTool(), ContentTool(), AttachmentsTool()]
    return {tool.name: tool for tool in tools}


def describe_tools(tools: Iterable[Tool]) -> str:
    lines = []
    for tool in tools:
        lines.append(f"- {tool.name}: {tool.description}")
    return "\n".join(lines)
