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

    profile: str = Field(default="openai")
    provider: str = Field(default="openai")
    model: str = Field(default="gpt-4.1-mini")
    temperature: float = Field(default=0.0)
    api_base: str | None = Field(default=None)
    api_key: str | None = Field(default=None)
    model_choices: list[str] = Field(default_factory=list)
    max_turns: int = Field(default=8)
    default_config_path: str = Field(default="configs/default.yaml")


def load_yaml(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    payload = yaml.safe_load(p.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _pick_env(name: str, fallback: Any) -> Any:
    value = os.getenv(name)
    return value if value not in (None, "") else fallback


def _parse_model_choices(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def _parse_int(raw: Any, fallback: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return fallback
    return value if value > 0 else fallback


def _parse_float(raw: Any, fallback: float) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return fallback


def load_config(path: str | Path | None = None) -> tuple[AppConfig, dict[str, Any]]:
    default_path = Path(path or os.getenv("MY_AGENT_APP_DEFAULT_CONFIG_PATH", "configs/default.yaml"))
    merged = load_yaml(default_path)
    profiles = merged.get("profiles")
    profile_map = profiles if isinstance(profiles, dict) else {}

    active_profile = str(_pick_env("MY_AGENT_APP_PROFILE", merged.get("profile", "openai")))
    selected_profile = profile_map.get(active_profile, {})
    selected = selected_profile if isinstance(selected_profile, dict) else {}

    raw_temp = _pick_env("MY_AGENT_APP_TEMPERATURE", selected.get("temperature", merged.get("temperature", 0.0)))
    raw_choices = _pick_env(
        "MY_AGENT_APP_MODEL_CHOICES",
        selected.get("model_choices", merged.get("model_choices", [])),
    )
    raw_turns = _pick_env("MY_AGENT_APP_MAX_TURNS", selected.get("max_turns", merged.get("max_turns", 8)))

    payload = {
        "profile": active_profile,
        "provider": _pick_env("MY_AGENT_APP_PROVIDER", selected.get("provider", merged.get("provider", "openai"))),
        "model": _pick_env("MY_AGENT_APP_MODEL", selected.get("model", merged.get("model", "gpt-4.1-mini"))),
        "temperature": _parse_float(raw_temp, 0.0),
        "api_base": _pick_env("MY_AGENT_APP_API_BASE", selected.get("api_base", merged.get("api_base"))),
        "api_key": _pick_env("MY_AGENT_APP_API_KEY", selected.get("api_key", merged.get("api_key"))),
        "model_choices": _parse_model_choices(raw_choices),
        "max_turns": _parse_int(raw_turns, 8),
        "default_config_path": str(default_path),
    }

    if hasattr(AppConfig, "model_validate"):
        cfg = AppConfig.model_validate(payload)
    else:
        cfg = AppConfig(**payload)
    return cfg, merged
