"""Debug helpers."""

from __future__ import annotations

import platform
import sys


def runtime_info() -> dict[str, str]:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
