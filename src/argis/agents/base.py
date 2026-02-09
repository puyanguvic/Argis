"""Main application agent wrapper."""

from __future__ import annotations

import uuid

from engine.argis import ArgisEngine
from protocol.events import Error, TaskComplete
from protocol.op import UserInput


class MainAgent:
    def __init__(self, engine: ArgisEngine | None = None) -> None:
        self.engine = engine or ArgisEngine()

    def run(self, input_kind: str, payload: object, record_path: str | None = None) -> dict:
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        options = {"record_path": record_path} if record_path else {}
        events = self.engine.submit(
            UserInput(
                session_id="argis",
                task_id=task_id,
                input_kind=input_kind,
                payload=payload,
                options=options,
            )
        )
        artifacts: dict[str, dict] = {}
        for event in events:
            if isinstance(event, Error):
                raise RuntimeError(event.message)
            if isinstance(event, TaskComplete):
                for artifact in event.artifacts:
                    artifacts[artifact.kind] = artifact.payload
        return artifacts
