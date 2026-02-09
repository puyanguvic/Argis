"""Config loader from env + yaml."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Any

import yaml
from pydantic import BaseModel, Field

try:  # pragma: no cover
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ModuleNotFoundError:  # pragma: no cover
    BaseSettings = BaseModel  # type: ignore[misc,assignment]
    SettingsConfigDict = dict  # type: ignore[misc,assignment]


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MY_AGENT_APP_", extra="ignore")

    provider: str = Field(default="ollama")
    model: str = Field(default="llama3.1:8b")
    temperature: float = Field(default=0.0)
    default_config_path: str = Field(default="configs/default.yaml")


def load_yaml(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    payload = yaml.safe_load(p.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def load_config(path: str | Path | None = None) -> tuple[AppConfig, dict[str, Any]]:
    if hasattr(AppConfig, "model_validate"):
        cfg = AppConfig.model_validate(
            {
                "provider": os.getenv("MY_AGENT_APP_PROVIDER", "ollama"),
                "model": os.getenv("MY_AGENT_APP_MODEL", "llama3.1:8b"),
                "temperature": float(os.getenv("MY_AGENT_APP_TEMPERATURE", "0.0")),
                "default_config_path": os.getenv(
                    "MY_AGENT_APP_DEFAULT_CONFIG_PATH", "configs/default.yaml"
                ),
            }
        )
    else:
        cfg = AppConfig()
    merged = load_yaml(path or cfg.default_config_path)
    return cfg, merged
