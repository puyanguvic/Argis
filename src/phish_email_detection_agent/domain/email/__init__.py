"""Email domain models and parsing."""

from phish_email_detection_agent.domain.email.models import EmailInput
from phish_email_detection_agent.domain.email.parse import (
    extract_urls_from_html,
    parse_eml_content,
    parse_input_payload,
    summarize_chain_flags,
)

__all__ = [
    "EmailInput",
    "extract_urls_from_html",
    "parse_eml_content",
    "parse_input_payload",
    "summarize_chain_flags",
]
