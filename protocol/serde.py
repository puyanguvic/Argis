"""JSON serialization helpers for protocol messages."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from typing import Any, Dict, Type

from protocol import events as events_mod
from protocol import op as op_mod
from protocol.types import SessionConfig


_OP_REGISTRY: Dict[str, Type[op_mod.Op]] = {
    "ConfigureSession": op_mod.ConfigureSession,
    "UserInput": op_mod.UserInput,
    "Interrupt": op_mod.Interrupt,
    "Approval": op_mod.Approval,
}

_EVENT_REGISTRY: Dict[str, Type[events_mod.EventMsg]] = {
    "SessionConfigured": events_mod.SessionConfigured,
    "AgentMessage": events_mod.AgentMessage,
    "ApprovalRequest": events_mod.ApprovalRequest,
    "TurnComplete": events_mod.TurnComplete,
    "TaskComplete": events_mod.TaskComplete,
    "Error": events_mod.Error,
}


def _encode_dataclass(value: Any) -> Any:
    if is_dataclass(value):
        payload = asdict(value)
        payload["type"] = value.__class__.__name__
        return payload
    return value


def dumps(obj: Any) -> str:
    """Serialize a protocol message or payload to JSON."""

    return json.dumps(obj, default=_encode_dataclass, ensure_ascii=True)


def _inflate_session_config(data: Dict[str, Any]) -> None:
    config = data.get("config")
    if isinstance(config, dict):
        data["config"] = SessionConfig(**config)


def loads_op(payload: str) -> op_mod.Op:
    """Deserialize a JSON payload into an Op."""

    data = json.loads(payload)
    type_name = data.pop("type", "")
    cls = _OP_REGISTRY.get(type_name)
    if not cls:
        raise ValueError(f"Unknown op type: {type_name}")
    _inflate_session_config(data)
    return cls(**data)


def loads_event(payload: str) -> events_mod.EventMsg:
    """Deserialize a JSON payload into an EventMsg."""

    data = json.loads(payload)
    type_name = data.pop("type", "")
    cls = _EVENT_REGISTRY.get(type_name)
    if not cls:
        raise ValueError(f"Unknown event type: {type_name}")
    return cls(**data)
