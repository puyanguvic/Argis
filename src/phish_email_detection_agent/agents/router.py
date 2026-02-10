"""Simple routing agent."""

from __future__ import annotations


def route_text(text: str) -> str:
    size = len(text or "")
    if size < 160:
        return "FAST"
    if size > 1200:
        return "DEEP"
    return "STANDARD"
