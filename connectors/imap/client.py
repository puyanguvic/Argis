"""IMAP connector placeholder."""

from __future__ import annotations

from typing import Any, Dict


class ImapClient:
    def __init__(self, host: str, credentials: Dict[str, Any]) -> None:
        self.host = host
        self.credentials = credentials

    def fetch_message(self, message_id: str) -> Dict[str, Any]:
        raise NotImplementedError("IMAP connector not wired in this build.")
