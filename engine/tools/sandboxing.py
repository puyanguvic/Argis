"""Sandbox policy placeholders for tool execution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SandboxPolicy:
    allow_network: bool = False
    allow_fs_write: bool = False
