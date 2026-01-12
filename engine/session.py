"""Session state for the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict

from connectors.base import Connector
from engine.config import AgentConfig
from engine.orchestrator import AgentOrchestrator
from engine.task import Task
from providers.model.base import ModelProvider


@dataclass
class Session:
    session_id: str
    config: AgentConfig
    orchestrator: AgentOrchestrator
    provider: ModelProvider | None = None
    connector: Connector | None = None
    provider_name: str | None = None
    connector_name: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tasks: Dict[str, Task] = field(default_factory=dict)
