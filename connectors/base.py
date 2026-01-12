"""Connector interface for external ingestion sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

from schemas.email_schema import EmailInput


class Connector(ABC):
    name: str

    @abstractmethod
    def fetch_email(self, message_id: str) -> EmailInput:
        """Fetch and normalize a message into EmailInput."""
