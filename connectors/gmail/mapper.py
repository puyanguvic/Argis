"""Map Gmail API messages to EmailInput artifacts."""

from __future__ import annotations

from typing import Any, Dict


def map_gmail_message(message: Dict[str, Any]) -> Dict[str, Any]:
    raise NotImplementedError("Gmail mapper not implemented.")
