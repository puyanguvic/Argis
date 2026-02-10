"""Budget-aware routing and early-exit policy."""

from __future__ import annotations


class PipelinePolicy:
    """Simple policy object for route selection and early exits."""

    def route_text(self, text: str) -> str:
        size = len(text or "")
        if size < 160:
            return "FAST"
        if size > 1200:
            return "DEEP"
        return "STANDARD"

    def should_early_exit(self, *, has_content: bool) -> bool:
        return not has_content


def route_text(text: str) -> str:
    return PipelinePolicy().route_text(text)
