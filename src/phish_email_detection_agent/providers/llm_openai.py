"""OpenAI and provider model reference builder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from phish_email_detection_agent.providers.llm_ollama import build_ollama_model_reference


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    model: str
    api_base: str | None = None
    api_key: str | None = None


def build_model_reference(cfg: ProviderConfig) -> Any:
    provider = (cfg.provider or "openai").strip().lower()
    if provider in {"local", "ollama"}:
        return build_ollama_model_reference(
            model=cfg.model,
            api_base=cfg.api_base,
            api_key=cfg.api_key,
        )
    return cfg.model
