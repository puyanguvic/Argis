import json

import pytest

from phish_email_detection_agent.agents.skills import SkillExecutionError, SkillRegistry, SkillSpec
from phish_email_detection_agent.cli import run_once


def test_skill_registry_rejects_non_whitelisted_skill():
    registry = SkillRegistry(allowed_names={"EmailSurface"})
    with pytest.raises(ValueError):
        registry.register(
            spec=SkillSpec(name="UnknownSkill", description="nope"),
            runner=lambda: None,
        )


def test_skill_registry_rejects_large_step_count():
    registry = SkillRegistry()
    with pytest.raises(ValueError):
        registry.register(
            spec=SkillSpec(name="TooLong", description="invalid", max_steps=6),
            runner=lambda: None,
        )


def test_skill_registry_errors_on_unknown_execution():
    registry = SkillRegistry()
    with pytest.raises(SkillExecutionError):
        registry.run("NotRegistered")


def test_precheck_exposes_fixed_skill_chain():
    result = json.loads(run_once("Subject: hello\n\nquick ping"))
    precheck = result["precheck"]
    assert "skill_whitelist" in precheck
    assert "skill_chain" in precheck
    assert "skill_trace" in precheck
    assert precheck["skill_whitelist"][:5] == [
        "EmailSurface",
        "HeaderAnalysis",
        "URLRisk",
        "NLPCues",
        "AttachmentSurface",
    ]
    assert precheck["skill_chain"][:5] == [
        "EmailSurface",
        "HeaderAnalysis",
        "URLRisk",
        "NLPCues",
        "AttachmentSurface",
    ]
    assert all(item["status"] == "done" for item in precheck["skill_trace"])
