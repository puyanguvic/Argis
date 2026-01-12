"""Protocol-driven engine loop with Session/Task/Turn state."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional
import uuid

from engine.bootstrap import AppConfig, load_app_config, load_connector, load_provider
from engine.orchestrator import AgentOrchestrator
from engine.queuepair import QueuePair
from engine.report import build_report
from engine.session import Session
from engine.task import Task
from engine.turn import Turn, run_turn
from protocol.events import AgentMessage, Error, EventMsg, SessionConfigured, TaskComplete, TurnComplete
from protocol.op import Approval, ConfigureSession, Interrupt, Op, UserInput
from protocol.types import Artifact, ResponseBookmark, SessionConfig


class ArgisEngine:
    """Core engine that processes Ops and emits EventMsg objects."""

    def __init__(
        self,
        queues: Optional[QueuePair] = None,
        default_config_path: Optional[str | Path] = None,
    ) -> None:
        self.queues = queues or QueuePair()
        self.sessions: Dict[str, Session] = {}
        self.default_config_path = Path(default_config_path) if default_config_path else None
        self.app_config: AppConfig = load_app_config()

    def submit(self, op: Op) -> list[EventMsg]:
        """Submit an op and return emitted events."""

        self.queues.submit(op)
        self._process()
        return list(self.queues.drain_events())

    def _process(self) -> None:
        while self.queues.has_submissions():
            op = self.queues.pop_submission()
            if isinstance(op, ConfigureSession):
                self._configure_session(op)
            elif isinstance(op, UserInput):
                self._handle_user_input(op)
            elif isinstance(op, Interrupt):
                self.queues.emit(
                    AgentMessage(
                        session_id=op.session_id,
                        content="Interrupt received (no active cancellation support yet).",
                        level="warning",
                    )
                )
            elif isinstance(op, Approval):
                self.queues.emit(
                    AgentMessage(
                        session_id=op.session_id,
                        content="Approval received (no gated operations in this build).",
                        level="info",
                    )
                )
            else:
                self.queues.emit(
                    Error(session_id=op.session_id, message="Unknown op type", detail=asdict(op))
                )

    def _configure_session(self, op: ConfigureSession) -> None:
        config_path = self._resolve_config_path(op.config)
        provider_name = self._resolve_provider_name(op.config)
        connector_name = self._resolve_connector_name(op.config)
        provider = load_provider(provider_name)
        connector = load_connector(connector_name)
        orchestrator = AgentOrchestrator(
            config_path=config_path,
            provider=provider,
            connector=connector,
        )
        session = Session(
            session_id=op.session_id,
            config=orchestrator.config,
            orchestrator=orchestrator,
            provider=provider,
            connector=connector,
            provider_name=provider_name,
            connector_name=connector_name,
        )
        self.sessions[op.session_id] = session
        self.queues.emit(
            SessionConfigured(
                session_id=op.session_id,
                config={
                    "profile": op.config.profile,
                    "config_path": str(config_path) if config_path else None,
                    "provider": op.config.provider,
                    "connector": op.config.connector,
                    "options": dict(op.config.options),
                },
            )
        )

    def _resolve_config_path(self, config: SessionConfig) -> Optional[Path]:
        if config.profile:
            profile_path = Path("configs/profiles") / f"{config.profile}.yaml"
            if profile_path.exists():
                return profile_path
        if config.config_path:
            return Path(config.config_path)
        candidate: Optional[Path] = None
        if self.app_config.profile_path:
            candidate = Path(self.app_config.profile_path)
        elif self.app_config.profile:
            candidate = Path("configs/profiles") / f"{self.app_config.profile}.yaml"
        if candidate and candidate.exists():
            return candidate
        if self.default_config_path:
            return self.default_config_path
        for candidate in (
            Path("configs/profiles/balanced.yaml"),
            Path("configs/default.yaml"),
        ):
            if candidate.exists():
                return candidate
        return None

    def _ensure_session(self, session_id: str) -> Session:
        session = self.sessions.get(session_id)
        if session:
            return session
        config_path = self._resolve_config_path(SessionConfig())
        provider_name = self._resolve_provider_name(SessionConfig())
        connector_name = self._resolve_connector_name(SessionConfig())
        provider = load_provider(provider_name)
        connector = load_connector(connector_name)
        orchestrator = AgentOrchestrator(
            config_path=config_path,
            provider=provider,
            connector=connector,
        )
        session = Session(
            session_id=session_id,
            config=orchestrator.config,
            orchestrator=orchestrator,
            provider=provider,
            connector=connector,
            provider_name=provider_name,
            connector_name=connector_name,
        )
        self.sessions[session_id] = session
        return session

    def _handle_user_input(self, op: UserInput) -> None:
        session = self._ensure_session(op.session_id)
        task_id = op.task_id or f"task-{uuid.uuid4().hex[:8]}"
        task = Task(
            task_id=task_id,
            input_kind=op.input_kind,
            payload=op.payload,
            options=dict(op.options),
        )
        session.tasks[task_id] = task
        turn = Turn(turn_id=f"turn-{uuid.uuid4().hex[:8]}")
        task.turns.append(turn)

        try:
            if op.input_kind == "connector":
                result = self._run_connector_turn(session, op.payload, op.options)
            else:
                result = run_turn(
                    session.orchestrator,
                    op.input_kind,
                    op.payload,
                    op.options,
                )
            turn.result = result
            turn.status = "completed"
            turn.finished_at = datetime.now(timezone.utc)
            artifacts = list(_build_artifacts(result))
            bookmark = ResponseBookmark(
                trace_id=result.trace_id,
                task_id=task_id,
                turn_id=turn.turn_id,
            )
            self.queues.emit(
                TurnComplete(
                    session_id=session.session_id,
                    task_id=task_id,
                    turn_id=turn.turn_id,
                    bookmark=bookmark,
                )
            )
            self.queues.emit(
                TaskComplete(
                    session_id=session.session_id,
                    task_id=task_id,
                    artifacts=artifacts,
                    bookmark=bookmark,
                )
            )
            task.status = "completed"
        except Exception as exc:  # pragma: no cover - defensive error channel
            turn.status = "failed"
            turn.finished_at = datetime.now(timezone.utc)
            task.status = "failed"
            self.queues.emit(
                Error(
                    session_id=session.session_id,
                    message=str(exc),
                    detail={"task_id": task_id, "input_kind": op.input_kind},
                )
            )

    def _resolve_provider_name(self, config: SessionConfig) -> Optional[str]:
        return config.provider or self.app_config.provider

    def _resolve_connector_name(self, config: SessionConfig) -> Optional[str]:
        return config.connector or self.app_config.connector

    def _run_connector_turn(
        self,
        session: Session,
        payload: object,
        options: Dict[str, object],
    ):
        if session.connector is None:
            raise ValueError("Connector input requested, but no connector is configured.")
        message_id = _extract_message_id(payload)
        email = session.connector.fetch_email(message_id)
        record_path = options.get("record_path")
        return session.orchestrator.detect(email, record_path=record_path)


def _build_artifacts(result) -> Iterable[Artifact]:
    profile = result.evidence.plan.path if result.evidence.plan else result.evidence.path
    payload = {
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "trace_id": result.trace_id,
        "profile": profile,
        "summary": result.email.summary() if result.email else None,
        "explanation": result.explanation.model_dump(),
        "evidence": result.evidence.model_dump(),
        "runtime_ms": result.runtime_ms,
    }
    yield Artifact(kind="detection_result", payload=payload)
    yield Artifact(kind="report_md", payload={"text": build_report(result)})


def _extract_message_id(payload: object) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict) and "message_id" in payload:
        return str(payload["message_id"])
    raise ValueError("Connector input payload must include message_id.")
