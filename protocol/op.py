"""Protocol operations submitted from UI to the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from protocol.types import SessionConfig


@dataclass(frozen=True)
class Op:
    session_id: str


@dataclass(frozen=True)
class ConfigureSession(Op):
    config: SessionConfig = field(default_factory=SessionConfig)


@dataclass(frozen=True)
class UserInput(Op):
    input_kind: str
    payload: Any
    options: Dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None


@dataclass(frozen=True)
class Interrupt(Op):
    reason: Optional[str] = None


@dataclass(frozen=True)
class Approval(Op):
    request_id: str
    approved: bool
    note: Optional[str] = None
