"""Default model/runtime parameters."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelConfig:
    name: str = "llama3.1:8b"
    temperature: float = 0.0
    max_tokens: int = 512
