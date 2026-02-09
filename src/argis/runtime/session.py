"""Optional in-memory session store."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SessionState:
    session_id: str
    history: list[dict] = field(default_factory=list)

    def append(self, item: dict) -> None:
        self.history.append(item)
