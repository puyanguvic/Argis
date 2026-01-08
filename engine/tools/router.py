"""Tool resolution helpers."""

from __future__ import annotations

from typing import Iterable, List

from engine.tools.registry import ToolRegistry


def resolve_tools(tool_names: Iterable[str], registry: ToolRegistry) -> List:
    resolved = []
    for name in tool_names:
        handler = registry.get(name)
        if handler:
            resolved.append(handler)
    return resolved
