"""Skill primitives and discovery utilities."""

from phish_email_detection_agent.skills.catalog import (
    InstalledSkill,
    default_skills_dir,
    discover_installed_skills,
)
from phish_email_detection_agent.skills.fixed_chain import FIXED_SKILL_CHAIN, fixed_skill_spec
from phish_email_detection_agent.skills.registry import (
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
    "FIXED_SKILL_CHAIN",
    "fixed_skill_spec",
]
