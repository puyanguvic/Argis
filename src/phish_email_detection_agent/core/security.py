"""Centralized security defaults for network and prompt boundaries."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress


@dataclass(frozen=True)
class SecurityPolicy:
    connect_timeout_s: float = 3.0
    total_timeout_s: float = 8.0
    max_response_bytes: int = 1_000_000
    max_redirects: int = 3
    allow_private_network: bool = False
    user_agent: str = "ArgisSafeFetcher/3.0"
    allow_cookies: bool = False


def is_private_or_local_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )
