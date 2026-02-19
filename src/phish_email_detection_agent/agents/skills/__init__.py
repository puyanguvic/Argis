"""Skill registry primitives for fixed, whitelisted pipelines."""

from phish_email_detection_agent.agents.skills.registry import (
    SkillExecutionError,
    SkillRegistry,
    SkillSpec,
)

__all__ = ["SkillSpec", "SkillRegistry", "SkillExecutionError"]
