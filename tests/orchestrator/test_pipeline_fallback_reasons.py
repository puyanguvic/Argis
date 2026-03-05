from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from phish_email_detection_agent.domain.email.models import EmailInput
from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy
from phish_email_detection_agent.orchestrator.stages.evidence_builder import EvidenceBuilder
from phish_email_detection_agent.orchestrator.stages.executor import PipelineExecutor
from phish_email_detection_agent.orchestrator.stages.judge import JudgeEngine, JudgeRunResult


class _Service:
    provider = "local"
    max_turns = 4
    pipeline_policy = PipelinePolicy()

    def can_call_remote(self) -> bool:
        return True

    def build_common_kwargs(self) -> dict[str, object]:
        return {}

    def event(
        self,
        stage: str,
        status: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"type": "event", "stage": stage, "status": status, "message": message, "data": data or {}}


@dataclass
class _FallbackResult:
    provider: str = "local"

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return {
            "verdict": "phishing",
            "reason": "fallback",
            "path": "STANDARD",
            "risk_score": 35,
            "confidence": 0.35,
            "email_label": "phish_email",
            "is_spam": False,
            "is_phish_email": True,
            "spam_score": 7,
            "threat_tags": [],
            "indicators": ["runtime:fallback"],
            "recommended_actions": ["review"],
            "input": "",
            "urls": [],
            "attachments": [],
            "provider_used": f"{self.provider}:fallback",
            "evidence": {},
        }


def _fallback_builder(email, provider, evidence_pack, precheck, *, pipeline_policy):
    return _FallbackResult(provider=provider)


def _minimal_pack() -> EvidencePack:
    return EvidencePack.model_validate(
        {
            "email_meta": {"message_id": "m1"},
            "header_signals": {},
            "pre_score": {"risk_score": 48, "route": "review", "reasons": ["unit:test"]},
        }
    )


def test_parse_error_returns_fallback_with_reason():
    def _parse(_text: str):
        raise ValueError("bad parse")

    executor = PipelineExecutor(
        parse_input=_parse,
        evidence_builder=EvidenceBuilder(lambda email, service: (_minimal_pack(), {"combined_urls": [], "indicators": []})),
        skill_router=SimpleNamespace(
            plan=lambda **kwargs: SimpleNamespace(
                has_content=True,
                route="review",
                path="STANDARD",
                should_invoke_judge=False,
                reasons=["unit:test"],
            )
        ),
        judge=JudgeEngine(),
        fallback_builder=_fallback_builder,
    )

    result = executor.analyze(service=_Service(), text="hello")
    assert result["provider_used"].endswith(":fallback")
    assert result["fallback_reason"] == "parse_error:ValueError"


def test_evidence_build_error_returns_fallback_with_reason():
    def _build(_email, _service):
        raise RuntimeError("build failed")

    executor = PipelineExecutor(
        parse_input=lambda text: EmailInput(text=text),
        evidence_builder=EvidenceBuilder(_build),
        skill_router=SimpleNamespace(
            plan=lambda **kwargs: SimpleNamespace(
                has_content=True,
                route="review",
                path="STANDARD",
                should_invoke_judge=False,
                reasons=["unit:test"],
            )
        ),
        judge=JudgeEngine(),
        fallback_builder=_fallback_builder,
    )

    result = executor.analyze(service=_Service(), text="hello")
    assert result["provider_used"].endswith(":fallback")
    assert result["fallback_reason"] == "evidence_build_error:RuntimeError"


def test_judge_error_returns_fallback_with_reason():
    class _Router:
        @staticmethod
        def plan(**kwargs):
            return SimpleNamespace(
                has_content=True,
                route="review",
                path="STANDARD",
                should_invoke_judge=True,
                reasons=["unit:test"],
            )

    class _Judge:
        @staticmethod
        def evaluate(**kwargs):
            return JudgeRunResult(final_result=None, judge_output=None, error=RuntimeError("judge failed"))

    executor = PipelineExecutor(
        parse_input=lambda text: EmailInput(text=text),
        evidence_builder=EvidenceBuilder(
            lambda email, service: (_minimal_pack(), {"combined_urls": [], "indicators": ["unit:test"]})
        ),
        skill_router=_Router(),
        judge=_Judge(),  # type: ignore[arg-type]
        fallback_builder=_fallback_builder,
    )

    result = executor.analyze(service=_Service(), text="hello")
    assert result["provider_used"].endswith(":fallback")
    assert result["fallback_reason"] == "judge_error:RuntimeError"
