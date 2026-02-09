"""Session strategies."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InMemorySession:
    history: list[dict[str, object]] = field(default_factory=list)

    def add(self, item: dict[str, object]) -> None:
        self.history.append(item)
