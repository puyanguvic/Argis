"""Utility helpers for URL handling."""

from __future__ import annotations

import re
from typing import Iterable, List

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def extract_urls(texts: Iterable[str | None]) -> List[str]:
    """Extract URLs from a list of optional text inputs."""

    found: list[str] = []
    for text in texts:
        if not text:
            continue
        found.extend(URL_RE.findall(text))
    return [url.strip(").,;\"'") for url in found if url]
