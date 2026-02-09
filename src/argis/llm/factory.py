"""Factory for creating model providers."""

from __future__ import annotations

from typing import Any

from providers.model.registry import ModelRegistry


def create_provider(provider_name: str, **kwargs: Any):
    registry = ModelRegistry()
    provider_cls = registry.get(provider_name)
    if provider_cls is None:
        raise ValueError(f"Unsupported provider: {provider_name}")
    return provider_cls(**kwargs)
