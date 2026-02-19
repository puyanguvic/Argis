"""SkillsBench-style local skill discovery utilities."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re

_SKILL_MD = "SKILL.md"
_FRONT_MATTER_RE = re.compile(r"^\s*---\n(.*?)\n---\n?", re.DOTALL)


@dataclass(frozen=True)
class InstalledSkill:
    name: str
    description: str
    directory: str
    skill_md: str


def default_skills_dir() -> Path:
    configured = os.getenv("MY_AGENT_APP_SKILLS_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    # repo-root/src/phish_email_detection_agent/agents/skills/catalog.py -> repo-root/skills
    return Path(__file__).resolve().parents[4] / "skills"


def _parse_front_matter(text: str) -> dict[str, str]:
    match = _FRONT_MATTER_RE.match(text)
    if match is None:
        return {}
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        row = line.strip()
        if not row or row.startswith("#") or ":" not in row:
            continue
        key, raw = row.split(":", 1)
        values[key.strip()] = raw.strip().strip('"').strip("'")
    return values


def discover_installed_skills(skills_dir: Path | None = None) -> list[InstalledSkill]:
    root = (skills_dir or default_skills_dir()).expanduser()
    if not root.exists() or not root.is_dir():
        return []

    skills: list[InstalledSkill] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        skill_md = entry / _SKILL_MD
        if not skill_md.is_file():
            continue

        try:
            front_matter = _parse_front_matter(skill_md.read_text(encoding="utf-8"))
        except OSError:
            continue

        name = str(front_matter.get("name") or entry.name).strip() or entry.name
        description = str(front_matter.get("description") or "").strip()
        skills.append(
            InstalledSkill(
                name=name,
                description=description,
                directory=str(entry),
                skill_md=str(skill_md),
            )
        )
    return skills
