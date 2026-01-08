"""Registry for tool callables."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable

from engine.tools.spec import ToolSpec


@dataclass
class ToolRegistry:
    tools: Dict[str, Callable[..., object]] = field(default_factory=dict)
    specs: Dict[str, ToolSpec] = field(default_factory=dict)

    def register(self, spec: ToolSpec, handler: Callable[..., object]) -> None:
        self.tools[spec.name] = handler
        self.specs[spec.name] = spec

    def get(self, name: str) -> Callable[..., object] | None:
        return self.tools.get(name)

    def describe(self) -> Iterable[ToolSpec]:
        return self.specs.values()
