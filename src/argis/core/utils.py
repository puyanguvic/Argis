"""Small utility helpers used across the application package."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: str | Path) -> dict[str, Any]:
    candidate = Path(path)
    if not candidate.exists():
        return {}
    data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}
