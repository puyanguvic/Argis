from __future__ import annotations

from pathlib import Path
import re


_LEGACY_IMPORT_PATTERNS = (
    re.compile(r"\bfrom\s+phish_email_detection_agent\.agents\.skills(?:\b|\.)"),
    re.compile(r"\bimport\s+phish_email_detection_agent\.agents\.skills(?:\b|\.)"),
)

def _python_files() -> list[Path]:
    return [*Path("src").rglob("*.py"), *Path("tests").rglob("*.py")]


def test_no_new_legacy_agents_skills_imports():
    offenders: list[str] = []
    for path in _python_files():
        content = path.read_text(encoding="utf-8")
        if any(pattern.search(content) for pattern in _LEGACY_IMPORT_PATTERNS):
            offenders.append(path.as_posix())

    assert not offenders, (
        "Legacy import path `phish_email_detection_agent.agents.skills` has been removed. "
        "Use `phish_email_detection_agent.skills`.\n"
        f"Found in: {offenders}"
    )
