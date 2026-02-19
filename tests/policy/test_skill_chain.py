from phish_email_detection_agent.policy.fixed_chain import (
    FIXED_SKILL_CHAIN,
    SKILL_ATTACHMENT_DEEP,
    SKILL_ATTACHMENT_SURFACE,
    SKILL_EMAIL_SURFACE,
    SKILL_HEADER_ANALYSIS,
    SKILL_NLP_CUES,
    SKILL_PAGE_CONTENT,
    SKILL_RISK_FUSION,
    SKILL_URL_RISK,
    fixed_skill_spec,
)


def test_fixed_skill_chain_order_is_stable():
    assert FIXED_SKILL_CHAIN == (
        SKILL_EMAIL_SURFACE,
        SKILL_HEADER_ANALYSIS,
        SKILL_URL_RISK,
        SKILL_NLP_CUES,
        SKILL_ATTACHMENT_SURFACE,
        SKILL_PAGE_CONTENT,
        SKILL_ATTACHMENT_DEEP,
        SKILL_RISK_FUSION,
    )


def test_fixed_skill_specs_have_descriptions_and_limits():
    for name in FIXED_SKILL_CHAIN:
        spec = fixed_skill_spec(name)
        assert spec.name == name
        assert spec.version == "v1"
        assert spec.max_steps == 5
        assert spec.description
