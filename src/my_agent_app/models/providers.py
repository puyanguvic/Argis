"""Provider definitions and defaults."""

from __future__ import annotations

from enum import Enum


class Provider(str, Enum):
    OPENAI = "openai"
    LITELLM = "litellm"
    OLLAMA = "ollama"


DEFAULT_TEMPERATURE = 0.0
