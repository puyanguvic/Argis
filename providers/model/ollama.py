"""Ollama provider placeholder."""

from __future__ import annotations

from typing import Any

from providers.model.base import ModelProvider


class OllamaProvider(ModelProvider):
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        **_: Any,
    ) -> None:
        self.model = model
        self.base_url = base_url

    def generate(self, prompt: str, **kwargs: Any) -> str:
        raise NotImplementedError("Ollama provider not wired in this build.")
