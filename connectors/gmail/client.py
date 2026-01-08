"""Gmail API connector placeholder."""

from __future__ import annotations

from typing import Any, Dict


class GmailClient:
    def __init__(self, credentials: Dict[str, Any]) -> None:
        self.credentials = credentials

    def fetch_message(self, message_id: str) -> Dict[str, Any]:
        raise NotImplementedError("Gmail connector not wired in this build.")
