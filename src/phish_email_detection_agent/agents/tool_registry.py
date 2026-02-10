"""Tool registry used by agent runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib
import inspect
import os
import pkgutil
from typing import Callable

from phish_email_detection_agent.agents.router import route_text
from phish_email_detection_agent.tools.debug import runtime_info
from phish_email_detection_agent.tools.email import classify_attachment, extract_urls, is_suspicious_url
from phish_email_detection_agent.tools.text import contains_phishing_keywords, normalize_text


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


def _tool_runtime_info() -> dict[str, str]:
    """Return python/runtime diagnostic information."""

    return runtime_info()


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
            _tool_runtime_info,
        ):
            self.register_callable(func)

    def register_plugin_tools(self, package: str = "phish_email_detection_agent.tools.plugins") -> None:
        """Auto-discover plugin tools from a package.

        Any top-level function named `tool_*` is auto-registered.
        """

        try:
            pkg = importlib.import_module(package)
        except Exception:
            return

        for _, module_name, _ in pkgutil.iter_modules(pkg.__path__):
            if module_name.startswith("_"):
                continue
            module = importlib.import_module(f"{package}.{module_name}")
            for _, func in inspect.getmembers(module, inspect.isfunction):
                if func.__module__ == module.__name__ and func.__name__.startswith("tool_"):
                    self.register_callable(func)

    def register_external_modules_from_env(self) -> None:
        """Load extra tool modules from `MY_AGENT_APP_TOOL_MODULES`.

        Example:
        `MY_AGENT_APP_TOOL_MODULES=my_pkg.security.tools,my_pkg.mail.tools`
        """

        raw = os.getenv("MY_AGENT_APP_TOOL_MODULES", "")
        modules = [item.strip() for item in raw.split(",") if item.strip()]
        for module_name in modules:
            try:
                module = importlib.import_module(module_name)
            except Exception:
                continue
            for _, func in inspect.getmembers(module, inspect.isfunction):
                if func.__module__ == module.__name__ and func.__name__.startswith("tool_"):
                    self.register_callable(func)

    def register_all(self) -> None:
        self.register_default_tools()
        self.register_plugin_tools()
        self.register_external_modules_from_env()

    def export(self) -> list[object]:
        return list(self._tools)
