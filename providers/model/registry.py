"""Simple registry for model providers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Type

from providers.model.base import ModelProvider
from providers.model.ollama import OllamaProvider


@dataclass
class ModelRegistry:
    providers: Dict[str, Type[ModelProvider]] = field(
        default_factory=lambda: {"ollama": OllamaProvider}
    )

    def get(self, name: str) -> Type[ModelProvider] | None:
        return self.providers.get(name)
