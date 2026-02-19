from pathlib import Path

from phish_email_detection_agent.policy.catalog import (
    default_skillpacks_dir,
    discover_installed_skillpacks,
)


def test_default_skillpacks_dir_supports_env_override(monkeypatch, tmp_path: Path):
    custom = tmp_path / "custom-skillpacks"
    monkeypatch.setenv("MY_AGENT_APP_SKILLPACKS_DIR", str(custom))
    assert default_skillpacks_dir() == custom


def test_discover_installed_skillpacks_reads_front_matter(tmp_path: Path):
    skillpacks_root = tmp_path / "skillpacks"
    skill_dir = skillpacks_root / "image-ocr"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: image-ocr\ndescription: Extract text from images\n---\n# Image OCR\n",
        encoding="utf-8",
    )

    skillpacks = discover_installed_skillpacks(skillpacks_root)
    assert len(skillpacks) == 1
    assert skillpacks[0].name == "image-ocr"
    assert skillpacks[0].description == "Extract text from images"
    assert skillpacks[0].directory == str(skill_dir)


def test_discover_installed_skillpacks_falls_back_to_folder_name(tmp_path: Path):
    skillpacks_root = tmp_path / "skillpacks"
    unnamed = skillpacks_root / "threat-detection"
    unnamed.mkdir(parents=True)
    (unnamed / "SKILL.md").write_text("# Threat Detection\n", encoding="utf-8")

    discovered = discover_installed_skillpacks(skillpacks_root)
    assert len(discovered) == 1
    assert discovered[0].name == "threat-detection"
    assert discovered[0].description == ""
