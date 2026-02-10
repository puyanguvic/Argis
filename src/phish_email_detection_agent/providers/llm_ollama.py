"""LiteLLM/Ollama model adapter."""

from __future__ import annotations

from typing import Any


def build_ollama_model_reference(
    *,
    model: str,
    api_base: str | None = None,
    api_key: str | None = None,
) -> Any:
    from agents.extensions.models.litellm_model import LitellmModel

    return LitellmModel(
        model=model,
        base_url=api_base,
        api_key=api_key,
    )
