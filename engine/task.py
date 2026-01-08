"""Task state for a single user input."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

from engine.turn import Turn


@dataclass
class Task:
    task_id: str
    input_kind: str
    payload: Any
    options: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    turns: List[Turn] = field(default_factory=list)
    status: str = "pending"
