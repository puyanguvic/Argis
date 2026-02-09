"""Supported LLM providers."""

from __future__ import annotations

from enum import Enum


class ProviderName(str, Enum):
    OLLAMA = "ollama"
    OPENAI = "openai"
    LITELLM = "litellm"
