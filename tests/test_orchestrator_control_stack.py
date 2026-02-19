from types import SimpleNamespace

from phish_email_detection_agent.orchestrator.evidence_store import EvidenceStore
from phish_email_detection_agent.orchestrator.skill_router import SkillRouter
from phish_email_detection_agent.orchestrator.tool_executor import ToolExecutor
from phish_email_detection_agent.orchestrator.validator import OnlineValidator


def test_evidence_store_deduplicates_by_fingerprint():
    store = EvidenceStore()
    first = store.add(category="url", payload={"url": "https://example.com"}, source="tool:url")
    second = store.add(category="url", payload={"url": "https://example.com"}, source="tool:url")

    assert first.evidence_id == second.evidence_id
    assert len(store.all()) == 1
    assert store.refs() == [
        {
            "evidence_id": first.evidence_id,
            "category": "url",
            "source": "tool:url",
            "tags": [],
        }
    ]


def test_skill_router_routes_review_path_to_judge():
    router = SkillRouter()
    evidence_pack = SimpleNamespace(
        pre_score=SimpleNamespace(route="review", reasons=["url:login_intent"]),
        email_meta=SimpleNamespace(
            message_id="m1",
            sender="a@example.com",
            subject="review me",
            date="2026-01-01",
        ),
    )
    plan = router.plan(
        evidence_pack=evidence_pack,
        has_content=True,
        can_call_remote=True,
    )
    assert plan.route == "review"
    assert plan.should_invoke_judge is True
    assert plan.reasons == ["url:login_intent"]


def test_tool_executor_retries_before_success():
    attempts = {"count": 0}

    def _flaky_tool(*, value: int) -> int:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("boom")
        return value * 2

    executor = ToolExecutor(max_retries=1)
    result = executor.execute(tool_name="double", tool_fn=_flaky_tool, value=21)
    assert result.ok is True
    assert result.output == 42
    assert result.attempts == 2


def test_online_validator_detects_invalid_payload():
    validator = OnlineValidator()
    issues = validator.validate_triage_result(
        {
            "verdict": "totally-unknown",
            "risk_score": 999,
            "indicators": [],
            "evidence": None,
        }
    )
    codes = {item.code for item in issues}
    assert "invalid_verdict" in codes
    assert "invalid_risk_score_range" in codes
