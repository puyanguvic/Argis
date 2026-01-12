"""IMAP connector adapter."""

from __future__ import annotations

from typing import Any, Dict

from connectors.base import Connector
from connectors.imap.client import ImapClient
from connectors.imap.mapper import map_imap_message
from schemas.email_schema import EmailInput


class ImapConnector(Connector):
    name = "imap"

    def __init__(
        self,
        host: str | None = None,
        credentials: Dict[str, Any] | None = None,
        **_: Any,
    ) -> None:
        self.host = host or ""
        self.credentials = credentials or {}
        self.client = ImapClient(self.host, self.credentials)

    def fetch_email(self, message_id: str) -> EmailInput:
        message = self.client.fetch_message(message_id)
        payload = map_imap_message(message)
        return EmailInput.model_validate(payload)
