"""URL domain extraction and models."""

from phish_email_detection_agent.domain.url.extract import (
    canonicalize_url,
    extract_urls,
    is_suspicious_url,
    url_domain,
)
from phish_email_detection_agent.domain.url.models import UrlIndicator

__all__ = [
    "UrlIndicator",
    "extract_urls",
    "canonicalize_url",
    "url_domain",
    "is_suspicious_url",
]
