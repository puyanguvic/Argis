"""Gmail connector adapter."""

from __future__ import annotations

from typing import Any, Dict, List

from connectors.base import Connector
from connectors.gmail.client import GmailClient
from connectors.gmail.mapper import map_gmail_message
from schemas.email_schema import EmailInput


class GmailConnector(Connector):
    name = "gmail"

    def __init__(
        self,
        credentials: Dict[str, Any] | None = None,
        scopes: List[str] | None = None,
        **_: Any,
    ) -> None:
        self.credentials = credentials or {}
        self.scopes = scopes or []
        self.client = GmailClient(self.credentials)

    def fetch_email(self, message_id: str) -> EmailInput:
        message = self.client.fetch_message(message_id)
        payload = map_gmail_message(message)
        return EmailInput.model_validate(payload)
