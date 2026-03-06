import sys
import types
import json
from types import SimpleNamespace

from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy
from phish_email_detection_agent.orchestrator.stages.judge import JudgeEngine


class _FakeService:
    provider = "local"
    max_turns = 4
    pipeline_policy = PipelinePolicy()

    def build_common_kwargs(self) -> dict[str, object]:
        return {}


def _minimal_pack() -> EvidencePack:
    return EvidencePack.model_validate(
        {
            "email_meta": {"message_id": "m1"},
            "header_signals": {},
            "url_signals": [
                {
                    "url": "https://login.example/reset",
                    "final_domain": "login.example",
                    "risk_flags": ["login-intent"],
                    "confidence": 0.7,
                }
            ],
            "pre_score": {"risk_score": 48, "route": "review", "reasons": ["unit:test"]},
        }
    )


def test_judge_engine_evaluate_attaches_validation_issues(monkeypatch):
    captured = {}

    class _FakeAgent:
        def __init__(self, *args, **kwargs):
            pass

    class _FakeAgentOutputSchema:
        def __init__(self, *args, **kwargs):
            pass

    class _FakeRunner:
        @staticmethod
        def run_sync(*args, **kwargs):
            captured["input"] = args[1]
            return SimpleNamespace(
                final_output={
                    "verdict": "phishing",
                    "risk_score": 75,
                    "confidence": 0.9,
                    "top_evidence": [{"claim": "credential form", "evidence_path": "selected_url_signals[0]"}],
                    "recommended_actions": ["block sender"],
                    "missing_info": [],
                    "reason": "Strong phishing indicators.",
                }
            )

    monkeypatch.setitem(
        sys.modules,
        "agents",
        types.SimpleNamespace(
            Agent=_FakeAgent,
            AgentOutputSchema=_FakeAgentOutputSchema,
            Runner=_FakeRunner,
        ),
    )

    engine = JudgeEngine()
    result = engine.evaluate(
        service=_FakeService(),
        email=SimpleNamespace(subject="hello", text="hello", attachments=[]),
        evidence_pack=_minimal_pack(),
        precheck={"combined_urls": [], "indicators": []},
        fallback=SimpleNamespace(recommended_actions=["verify sender"], reason="fallback"),
    )

    assert result.error is None
    assert result.final_result is not None
    assert "validation_issues" in result.final_result
    assert isinstance(result.final_result["validation_issues"], list)
    payload = json.loads(captured["input"])
    assert "judge_context" in payload
    assert "evidence_pack" not in payload
    assert payload["judge_context"]["path"] == "STANDARD"
    assert "selected_url_signals" in payload["judge_context"]
    assert payload["judge_context"]["pre_score"]["evidence_id"].startswith("evd_")
    stored_judge = result.final_result["evidence"]["judge"]
    assert stored_judge["top_evidence"][0]["evidence_id"].startswith("evd_")


def test_judge_engine_validator_reports_missing_indicators():
    engine = JudgeEngine()
    issues = engine.validate_final_result(
        {
            "verdict": "phishing",
            "risk_score": 80,
            "indicators": [],
            "evidence": {"evidence_pack": {}},
        }
    )
    codes = {item.code for item in issues}
    assert "missing_indicators" in codes
