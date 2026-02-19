"""Skill registry primitives for fixed, whitelisted pipelines."""

from phish_email_detection_agent.agents.skills.catalog import (
    InstalledSkill,
    default_skills_dir,
    discover_installed_skills,
)
from phish_email_detection_agent.agents.skills.registry import (
    SkillExecutionError,
    SkillRegistry,
    SkillSpec,
)

__all__ = [
    "InstalledSkill",
    "SkillSpec",
    "SkillRegistry",
    "SkillExecutionError",
    "default_skills_dir",
    "discover_installed_skills",
]
