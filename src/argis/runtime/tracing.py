"""Tracing toggle strategy."""

from __future__ import annotations

import os


def tracing_enabled() -> bool:
    return os.getenv("ARGIS_TRACING", "0") == "1"
