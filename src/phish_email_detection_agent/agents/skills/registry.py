"""Lightweight registry for deterministic skill execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


SkillRunner = Callable[..., Any]


@dataclass(frozen=True)
class SkillSpec:
    name: str
    description: str
    version: str = "v1"
    max_steps: int = 5


class SkillExecutionError(RuntimeError):
    """Raised when attempting to execute an unknown skill."""


@dataclass
class SkillRegistry:
    """Whitelist-backed registry for fixed pipeline skills."""

    allowed_names: set[str] = field(default_factory=set)
    _entries: dict[str, tuple[SkillSpec, SkillRunner]] = field(default_factory=dict, init=False, repr=False)

    def register(self, *, spec: SkillSpec, runner: SkillRunner) -> None:
        name = str(spec.name).strip()
        if not name:
            raise ValueError("Skill name must be non-empty.")
        if spec.max_steps <= 0 or spec.max_steps > 5:
            raise ValueError(f"Skill '{name}' must declare 1..5 steps.")
        if self.allowed_names and name not in self.allowed_names:
            raise ValueError(f"Skill '{name}' is not in whitelist.")
        if name in self._entries:
            raise ValueError(f"Skill '{name}' already registered.")
        self._entries[name] = (spec, runner)

    def run(self, name: str, *args: Any, **kwargs: Any) -> Any:
        entry = self._entries.get(str(name).strip())
        if entry is None:
            raise SkillExecutionError(f"Skill '{name}' is not registered.")
        _, runner = entry
        return runner(*args, **kwargs)

    def spec(self, name: str) -> SkillSpec:
        entry = self._entries.get(str(name).strip())
        if entry is None:
            raise SkillExecutionError(f"Skill '{name}' is not registered.")
        spec, _ = entry
        return spec

    def specs(self) -> list[SkillSpec]:
        return [entry[0] for entry in self._entries.values()]
