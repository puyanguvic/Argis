"""Prompt template access."""

from __future__ import annotations

from pathlib import Path

from argis.core.utils import load_yaml


def load_prompts(path: str | Path = "configs/prompts.yaml") -> dict:
    return load_yaml(path)
