"""Protocol event messages emitted by the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from protocol.types import Artifact, ResponseBookmark


@dataclass(frozen=True)
class EventMsg:
    session_id: str


@dataclass(frozen=True)
class SessionConfigured(EventMsg):
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentMessage(EventMsg):
    content: str
    level: str = "info"


@dataclass(frozen=True)
class ApprovalRequest(EventMsg):
    request_id: str
    prompt: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TurnComplete(EventMsg):
    task_id: str
    turn_id: str
    bookmark: Optional[ResponseBookmark] = None


@dataclass(frozen=True)
class TaskComplete(EventMsg):
    task_id: str
    artifacts: list[Artifact] = field(default_factory=list)
    bookmark: Optional[ResponseBookmark] = None


@dataclass(frozen=True)
class Error(EventMsg):
    message: str
    detail: Dict[str, Any] = field(default_factory=dict)
