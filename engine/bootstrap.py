"""App-level configuration and runtime loader helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from connectors.base import Connector
from connectors.registry import ConnectorRegistry
from providers.model.base import ModelProvider
from providers.model.registry import ModelRegistry


APP_CONFIG_PATH = Path("configs/app.yaml")
PROVIDER_CONFIG_DIR = Path("configs/providers")
CONNECTOR_CONFIG_DIR = Path("configs/connectors")


@dataclass(frozen=True)
class AppConfig:
    profile: Optional[str] = None
    profile_path: Optional[str] = None
    provider: Optional[str] = None
    connector: Optional[str] = None


def load_app_config(path: Path = APP_CONFIG_PATH) -> AppConfig:
    if not path.exists():
        return AppConfig()
    data = yaml.safe_load(path.read_text()) or {}
    return AppConfig(
        profile=data.get("profile"),
        profile_path=data.get("profile_path"),
        provider=data.get("provider"),
        connector=data.get("connector"),
    )


def load_provider(
    name: Optional[str],
    config_dir: Path = PROVIDER_CONFIG_DIR,
) -> Optional[ModelProvider]:
    if not name:
        return None
    registry = ModelRegistry()
    provider_cls = registry.get(name)
    if provider_cls is None:
        return None
    config = _load_named_config(config_dir, name)
    return provider_cls(**config)


def load_connector(
    name: Optional[str],
    config_dir: Path = CONNECTOR_CONFIG_DIR,
) -> Optional[Connector]:
    if not name:
        return None
    config = _load_named_config(config_dir, name)
    if isinstance(config.get("enabled"), bool) and not config["enabled"]:
        return None
    registry = ConnectorRegistry()
    connector_cls = registry.get(name)
    if connector_cls is None:
        return None
    return connector_cls(**config)


def _load_named_config(config_dir: Path, name: str) -> Dict[str, Any]:
    path = config_dir / f"{name}.yaml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text())
    if isinstance(data, dict):
        return data
    return {}
