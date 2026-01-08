"""Run recorder for audit logging."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any


def _default_serializer(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _hash_state(state: Any) -> str:
    payload = json.dumps(state, sort_keys=True, default=_default_serializer)
    return sha256(payload.encode("utf-8")).hexdigest()


class RunRecorder:
    """Record node transitions to a JSONL file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._handle = self.path.open("a", encoding="utf-8")

    def record(self, node_name: str, input_state: Any, tool_outputs: Any) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "node_name": node_name,
            "input_state_hash": _hash_state(input_state),
            "tool_outputs": tool_outputs,
        }
        self._handle.write(json.dumps(entry, default=_default_serializer) + "\n")
        self._handle.flush()

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "RunRecorder":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
