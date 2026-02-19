from pathlib import Path

from phish_email_detection_agent.skills.catalog import default_skills_dir, discover_installed_skills


def test_default_skills_dir_supports_env_override(monkeypatch, tmp_path: Path):
    custom = tmp_path / "custom-skills"
    monkeypatch.setenv("MY_AGENT_APP_SKILLS_DIR", str(custom))
    assert default_skills_dir() == custom


def test_discover_installed_skills_reads_front_matter(tmp_path: Path):
    skills_root = tmp_path / "skills"
    skill_dir = skills_root / "image-ocr"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: image-ocr\ndescription: Extract text from images\n---\n# Image OCR\n",
        encoding="utf-8",
    )

    skills = discover_installed_skills(skills_root)
    assert len(skills) == 1
    assert skills[0].name == "image-ocr"
    assert skills[0].description == "Extract text from images"
    assert skills[0].directory == str(skill_dir)


def test_discover_installed_skills_falls_back_to_folder_name(tmp_path: Path):
    skills_root = tmp_path / "skills"
    unnamed = skills_root / "threat-detection"
    unnamed.mkdir(parents=True)
    (unnamed / "SKILL.md").write_text("# Threat Detection\n", encoding="utf-8")

    discovered = discover_installed_skills(skills_root)
    assert len(discovered) == 1
    assert discovered[0].name == "threat-detection"
    assert discovered[0].description == ""
