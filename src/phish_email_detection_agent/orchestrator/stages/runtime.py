"""Pipeline runtime contracts used by routing/executor/judge stages."""

from __future__ import annotations

from typing import Any, Protocol

from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy


class PipelineRuntime(Protocol):
    """Minimal runtime surface required by pipeline stages."""

    provider: str
    max_turns: int
    pipeline_policy: PipelinePolicy

    def can_call_remote(self) -> bool: ...

    def build_common_kwargs(self) -> dict[str, object]: ...

    def event(
        self,
        stage: str,
        status: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...
