"""Catalog utilities for built-in deterministic tools."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from phish_email_detection_agent.tools.openai import openai_tool_functions


@dataclass(frozen=True)
class BuiltinTool:
    name: str
    description: str
    module: str


@lru_cache(maxsize=1)
def _discover_builtin_tools_cached() -> tuple[BuiltinTool, ...]:
    tools: list[BuiltinTool] = []
    for item in openai_tool_functions():
        tools.append(
            BuiltinTool(
                name=item.__name__,
                description=str(item.__doc__ or "").strip(),
                module=item.__module__,
            )
        )
    return tuple(tools)


def discover_builtin_tools() -> list[BuiltinTool]:
    return list(_discover_builtin_tools_cached())
