"""External system connectors (email, IMAP, etc.)."""

from connectors.base import Connector
from connectors.registry import ConnectorRegistry

__all__ = ["Connector", "ConnectorRegistry"]
