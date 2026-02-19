from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy
from phish_email_detection_agent.orchestrator.skill_router import SkillRouter


def _make_evidence(route: str) -> EvidencePack:
    return EvidencePack.model_validate(
        {
            "email_meta": {},
            "header_signals": {},
            "pre_score": {"risk_score": 10, "route": route, "reasons": ["unit:test"]},
        }
    )


def test_skill_router_skips_judge_for_allow_route():
    router = SkillRouter()
    plan = router.plan(evidence_pack=_make_evidence("allow"), has_content=True, can_call_remote=True)
    assert plan.should_invoke_judge is False


def test_skill_router_invokes_judge_for_review_route():
    router = SkillRouter()
    plan = router.plan(evidence_pack=_make_evidence("review"), has_content=True, can_call_remote=True)
    assert plan.should_invoke_judge is True


def test_skill_router_skips_judge_without_content():
    router = SkillRouter()
    plan = router.plan(evidence_pack=_make_evidence("deep"), has_content=False, can_call_remote=True)
    assert plan.should_invoke_judge is False


def test_skill_router_can_always_judge_allow_route():
    router = SkillRouter()
    policy = PipelinePolicy(judge_allow_mode="always")
    plan = router.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is True


def test_skill_router_can_sample_allow_route():
    router = SkillRouter()
    policy = PipelinePolicy(judge_allow_mode="sampled", judge_allow_sample_rate=1.0, judge_allow_sample_salt="unit")
    plan = router.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is True


def test_skill_router_sampled_allow_route_respects_zero_rate():
    router = SkillRouter()
    policy = PipelinePolicy(judge_allow_mode="sampled", judge_allow_sample_rate=0.0, judge_allow_sample_salt="unit")
    plan = router.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is False


def test_policy_invalid_allow_mode_normalizes_to_never():
    router = SkillRouter()
    policy = PipelinePolicy(judge_allow_mode="random_mode", judge_allow_sample_rate=1.0, judge_allow_sample_salt="unit")
    plan = router.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is False
