"""Tool registry used by agent runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ToolRegistry:
    """Extensible registry for OpenAI Agents function tools."""

    _tools: list[object] = field(default_factory=list)

    def register_callable(self, func: Callable[..., object]) -> None:
        from agents import function_tool

        self._tools.append(function_tool(func))

    def register_default_tools(self) -> None:
        from phish_email_detection_agent.tools.openai.builtin import openai_tool_functions

        for func in openai_tool_functions():
            self.register_callable(func)

    def register_all(self) -> None:
        self.register_default_tools()

    def export(self) -> list[object]:
        return list(self._tools)
