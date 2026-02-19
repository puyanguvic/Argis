"""Deterministic tool execution wrapper with retry and telemetry."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable


ToolFn = Callable[..., Any]


@dataclass(frozen=True)
class ToolExecutionResult:
    ok: bool
    tool_name: str
    output: Any = None
    error: str | None = None
    attempts: int = 1
    elapsed_ms: int = 0


@dataclass
class ToolExecutor:
    """Wraps tool execution into a normalized result contract."""

    max_retries: int = 0

    def execute(self, *, tool_name: str, tool_fn: ToolFn, **kwargs: Any) -> ToolExecutionResult:
        attempts = 0
        max_attempts = max(1, int(self.max_retries) + 1)
        start = time.perf_counter()
        last_error: Exception | None = None

        for _ in range(max_attempts):
            attempts += 1
            try:
                output = tool_fn(**kwargs)
                return ToolExecutionResult(
                    ok=True,
                    tool_name=str(tool_name),
                    output=output,
                    attempts=attempts,
                    elapsed_ms=int((time.perf_counter() - start) * 1000),
                )
            except Exception as exc:  # pragma: no cover - caller-driven failures
                last_error = exc

        error_name = type(last_error).__name__ if last_error is not None else "UnknownError"
        return ToolExecutionResult(
            ok=False,
            tool_name=str(tool_name),
            error=error_name,
            attempts=attempts,
            elapsed_ms=int((time.perf_counter() - start) * 1000),
        )
