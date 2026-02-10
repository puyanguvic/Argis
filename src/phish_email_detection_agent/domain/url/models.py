"""URL domain-level models."""

from __future__ import annotations

from pydantic import BaseModel


class UrlIndicator(BaseModel):
    url: str
    domain: str = ""
    canonical_url: str = ""
    suspicious: bool = False
