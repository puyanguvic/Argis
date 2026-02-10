"""Provider and model selection for OpenAI Agents SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    model: str
    api_base: str | None = None
    api_key: str | None = None


def build_model_reference(cfg: ProviderConfig) -> Any:
    """Return model reference accepted by `agents.Agent`.

    - `openai`: model name string (SDK resolves via OpenAI client/env).
    - `local`: `LitellmModel` for local/third-party providers (e.g. Ollama).
    """

    provider = (cfg.provider or "openai").strip().lower()
    if provider in {"local", "ollama"}:
        from agents.extensions.models.litellm_model import LitellmModel

        return LitellmModel(
            model=cfg.model,
            base_url=cfg.api_base,
            api_key=cfg.api_key,
        )
    return cfg.model
