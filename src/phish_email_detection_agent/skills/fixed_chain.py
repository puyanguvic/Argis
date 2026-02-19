"""Fixed deterministic skill-chain definitions."""

from __future__ import annotations

from dataclasses import dataclass

from phish_email_detection_agent.skills.registry import SkillSpec


@dataclass(frozen=True)
class FixedSkillDefinition:
    name: str
    description: str
    version: str = "v1"
    max_steps: int = 5

    def to_spec(self) -> SkillSpec:
        return SkillSpec(
            name=self.name,
            description=self.description,
            version=self.version,
            max_steps=self.max_steps,
        )


SKILL_EMAIL_SURFACE = "EmailSurface"
SKILL_HEADER_ANALYSIS = "HeaderAnalysis"
SKILL_URL_RISK = "URLRisk"
SKILL_NLP_CUES = "NLPCues"
SKILL_ATTACHMENT_SURFACE = "AttachmentSurface"
SKILL_PAGE_CONTENT = "PageContentAnalysis"
SKILL_ATTACHMENT_DEEP = "AttachmentDeepAnalysis"
SKILL_RISK_FUSION = "RiskFusion"

FIXED_SKILL_DEFINITIONS: tuple[FixedSkillDefinition, ...] = (
    FixedSkillDefinition(
        name=SKILL_EMAIL_SURFACE,
        description="Extract visible/hidden links and normalize initial message surface.",
    ),
    FixedSkillDefinition(
        name=SKILL_HEADER_ANALYSIS,
        description="Parse SPF/DKIM/DMARC and relay-path anomalies.",
    ),
    FixedSkillDefinition(
        name=SKILL_URL_RISK,
        description="Evaluate URL/domain risk signals from extracted links.",
    ),
    FixedSkillDefinition(
        name=SKILL_NLP_CUES,
        description="Extract social-engineering and credential-theft text cues.",
    ),
    FixedSkillDefinition(
        name=SKILL_ATTACHMENT_SURFACE,
        description="Classify attachment surface risk before deep scan.",
    ),
    FixedSkillDefinition(
        name=SKILL_PAGE_CONTENT,
        description="Analyze fetched page content for credential-harvest indicators.",
    ),
    FixedSkillDefinition(
        name=SKILL_ATTACHMENT_DEEP,
        description="Run attachment deep scan and recover nested URL chains.",
    ),
    FixedSkillDefinition(
        name=SKILL_RISK_FUSION,
        description="Fuse skill outputs into deterministic pre-score route.",
    ),
)

FIXED_SKILL_CHAIN: tuple[str, ...] = tuple(item.name for item in FIXED_SKILL_DEFINITIONS)
_FIXED_SKILL_BY_NAME = {item.name: item for item in FIXED_SKILL_DEFINITIONS}


def fixed_skill_spec(name: str) -> SkillSpec:
    skill = _FIXED_SKILL_BY_NAME.get(str(name).strip())
    if skill is None:
        raise KeyError(f"Unknown fixed skill: {name!r}")
    return skill.to_spec()
