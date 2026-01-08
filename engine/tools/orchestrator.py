"""Placeholder for future tool orchestration logic."""

from __future__ import annotations

from typing import Iterable, List, Callable


def run_tools(tools: Iterable[Callable[[], object]]) -> List[object]:
    return [tool() for tool in tools]
