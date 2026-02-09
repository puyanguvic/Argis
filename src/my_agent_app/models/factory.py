"""Model object factory."""

from __future__ import annotations

from dataclasses import dataclass

from my_agent_app.models.presets import PRESETS


@dataclass(frozen=True)
class ModelHandle:
    provider: str
    model: str
    temperature: float = 0.0


def get_model(provider: str, model: str | None = None, temperature: float = 0.0) -> ModelHandle:
    resolved = model or PRESETS.get(provider, PRESETS["ollama"])
    return ModelHandle(provider=provider, model=resolved, temperature=temperature)
