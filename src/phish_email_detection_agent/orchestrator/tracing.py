"""Trace events schema helpers."""

from __future__ import annotations

from typing import Any

TraceEvent = dict[str, Any]


def make_event(stage: str, status: str, message: str, data: dict[str, Any] | None = None) -> TraceEvent:
    payload: TraceEvent = {
        "stage": stage,
        "status": status,
        "message": message,
    }
    if data:
        payload["data"] = data
    return payload
