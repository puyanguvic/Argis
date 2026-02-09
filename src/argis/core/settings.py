"""Unified settings loader for env + yaml configuration."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Any

from pydantic import BaseModel, Field

try:  # pragma: no cover - fallback path depends on environment deps
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ModuleNotFoundError:  # pragma: no cover
    BaseSettings = BaseModel  # type: ignore[misc,assignment]
    SettingsConfigDict = dict  # type: ignore[misc,assignment]

from argis.core.utils import load_yaml


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARGIS_", extra="ignore")

    profile: str = Field(default="balanced")
    provider: str = Field(default="ollama")
    connector: str = Field(default="")
    default_config_path: str = Field(default="configs/default.yaml")
    providers_config_path: str = Field(default="configs/providers.yaml")
    prompts_config_path: str = Field(default="configs/prompts.yaml")
    log_level: str = Field(default="INFO")


class SettingsBundle:
    def __init__(self, settings: AppSettings, config: dict[str, Any]) -> None:
        self.settings = settings
        self.config = config


def load_settings(config_path: str | Path | None = None) -> SettingsBundle:
    if hasattr(AppSettings, "model_validate"):
        settings = AppSettings.model_validate(
            {
                "profile": os.getenv("ARGIS_PROFILE", "balanced"),
                "provider": os.getenv("ARGIS_PROVIDER", "ollama"),
                "connector": os.getenv("ARGIS_CONNECTOR", ""),
                "default_config_path": os.getenv("ARGIS_DEFAULT_CONFIG_PATH", "configs/default.yaml"),
                "providers_config_path": os.getenv("ARGIS_PROVIDERS_CONFIG_PATH", "configs/providers.yaml"),
                "prompts_config_path": os.getenv("ARGIS_PROMPTS_CONFIG_PATH", "configs/prompts.yaml"),
                "log_level": os.getenv("ARGIS_LOG_LEVEL", "INFO"),
            }
        )
    else:
        settings = AppSettings()
    app_config_path = Path(config_path) if config_path else Path(settings.default_config_path)
    config = load_yaml(app_config_path)
    return SettingsBundle(settings=settings, config=config)
