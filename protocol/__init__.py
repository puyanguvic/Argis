"""Stable protocol types for UI <-> Engine communication."""

from protocol.events import (
    AgentMessage,
    ApprovalRequest,
    Error,
    EventMsg,
    SessionConfigured,
    TaskComplete,
    TurnComplete,
)
from protocol.op import Approval, ConfigureSession, Interrupt, Op, UserInput
from protocol.types import Artifact, ResponseBookmark, SessionConfig, ToolCall

__all__ = [
    "AgentMessage",
    "Approval",
    "ApprovalRequest",
    "Artifact",
    "ConfigureSession",
    "Error",
    "EventMsg",
    "Interrupt",
    "Op",
    "ResponseBookmark",
    "SessionConfig",
    "SessionConfigured",
    "TaskComplete",
    "ToolCall",
    "TurnComplete",
    "UserInput",
]
