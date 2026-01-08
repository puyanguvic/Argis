"""Protocol-level shared types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class SessionConfig:
    """Configuration requested by a UI client."""

    profile: Optional[str] = None
    config_path: Optional[str] = None
    provider: Optional[str] = None
    connector: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    """Generic tool call placeholder for future expansion."""

    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Artifact:
    """Serialized result payloads emitted by the engine."""

    kind: str
    payload: Dict[str, Any]


@dataclass(frozen=True)
class ResponseBookmark:
    """Stable bookmark for replay or incremental updates."""

    trace_id: Optional[str] = None
    task_id: Optional[str] = None
    turn_id: Optional[str] = None
