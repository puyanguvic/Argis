"""Model provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable


class ModelProvider(ABC):
    name: str

    @abstractmethod
    def generate(self, prompt: str, **kwargs: Any) -> str:
        """Generate a response for the given prompt."""

    def generate_stream(self, prompt: str, **kwargs: Any) -> Iterable[str]:
        """Optional streaming API; falls back to non-streaming."""

        yield self.generate(prompt, **kwargs)

    def metadata(self) -> Dict[str, Any]:
        return {"name": self.name}
