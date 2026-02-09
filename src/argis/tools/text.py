"""Text/structured parsing helpers."""

from __future__ import annotations

import json


def parse_json(value: str) -> dict:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object.")
    return payload


def compact_text(value: str) -> str:
    return " ".join((value or "").split())
