from phish_email_detection_agent.agents.pipeline.planner import Planner
from phish_email_detection_agent.agents.pipeline.policy import PipelinePolicy
from phish_email_detection_agent.domain.evidence import EvidencePack


def _make_evidence(route: str) -> EvidencePack:
    return EvidencePack.model_validate(
        {
            "email_meta": {},
            "header_signals": {},
            "pre_score": {"risk_score": 10, "route": route, "reasons": ["unit:test"]},
        }
    )


def test_planner_skips_judge_for_allow_route():
    planner = Planner()
    plan = planner.plan(evidence_pack=_make_evidence("allow"), has_content=True, can_call_remote=True)
    assert plan.should_invoke_judge is False


def test_planner_invokes_judge_for_review_route():
    planner = Planner()
    plan = planner.plan(evidence_pack=_make_evidence("review"), has_content=True, can_call_remote=True)
    assert plan.should_invoke_judge is True


def test_planner_skips_judge_without_content():
    planner = Planner()
    plan = planner.plan(evidence_pack=_make_evidence("deep"), has_content=False, can_call_remote=True)
    assert plan.should_invoke_judge is False


def test_planner_can_always_judge_allow_route():
    planner = Planner()
    policy = PipelinePolicy(judge_allow_mode="always")
    plan = planner.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is True


def test_planner_can_sample_allow_route():
    planner = Planner()
    policy = PipelinePolicy(judge_allow_mode="sampled", judge_allow_sample_rate=1.0, judge_allow_sample_salt="unit")
    plan = planner.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is True


def test_planner_sampled_allow_route_respects_zero_rate():
    planner = Planner()
    policy = PipelinePolicy(judge_allow_mode="sampled", judge_allow_sample_rate=0.0, judge_allow_sample_salt="unit")
    plan = planner.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is False


def test_policy_invalid_allow_mode_normalizes_to_never():
    planner = Planner()
    policy = PipelinePolicy(judge_allow_mode="random_mode", judge_allow_sample_rate=1.0, judge_allow_sample_salt="unit")
    plan = planner.plan(
        evidence_pack=_make_evidence("allow"),
        has_content=True,
        can_call_remote=True,
        pipeline_policy=policy,
    )
    assert plan.should_invoke_judge is False
