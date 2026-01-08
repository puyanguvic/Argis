"""Map IMAP messages to EmailInput artifacts."""

from __future__ import annotations

from typing import Any, Dict


def map_imap_message(message: Dict[str, Any]) -> Dict[str, Any]:
    raise NotImplementedError("IMAP mapper not implemented.")
