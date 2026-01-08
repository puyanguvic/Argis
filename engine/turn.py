"""Turn execution for a task."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict

from engine.orchestrator import AgentOrchestrator
from engine.player import replay_run
from engine.state import DetectionResult
from schemas.email_schema import EmailInput
from tools_builtin.parser import parse_raw_email


@dataclass
class Turn:
    turn_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    status: str = "running"
    result: DetectionResult | None = None


def run_turn(
    orchestrator: AgentOrchestrator,
    input_kind: str,
    payload: Any,
    options: Dict[str, Any],
) -> DetectionResult:
    """Execute a single turn and return the detection result."""

    record_path = options.get("record_path")
    if input_kind == "email_json":
        email = EmailInput.model_validate(payload)
        return orchestrator.detect(email, record_path=record_path)
    if input_kind == "raw_email":
        return orchestrator.detect_raw(str(payload), record_path=record_path)
    if input_kind == "recording":
        return replay_run(str(payload), config=orchestrator.config)
    raise ValueError(f"Unsupported input_kind: {input_kind}")
