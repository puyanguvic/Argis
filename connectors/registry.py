"""Registry for connector implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Type

from connectors.base import Connector
from connectors.gmail.connector import GmailConnector
from connectors.imap.connector import ImapConnector


@dataclass
class ConnectorRegistry:
    connectors: Dict[str, Type[Connector]] = field(
        default_factory=lambda: {"gmail": GmailConnector, "imap": ImapConnector}
    )

    def get(self, name: str) -> Type[Connector] | None:
        return self.connectors.get(name)
