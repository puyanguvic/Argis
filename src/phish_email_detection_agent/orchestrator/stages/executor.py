"""Executor stage orchestrating skill routing, evidence, and judge flow."""

from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Protocol

from phish_email_detection_agent.domain.email.models import EmailInput
from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.orchestrator.stages.evidence_builder import EvidenceBuilder
from phish_email_detection_agent.orchestrator.stages.judge import JudgeEngine
from phish_email_detection_agent.orchestrator.stages.runtime import PipelineRuntime


ParseInputFn = Callable[[str], Any]
FallbackFn = Callable[..., Any]
_FALLBACK_EMPTY_INPUT = "empty_input"
_FALLBACK_REMOTE_UNAVAILABLE = "remote_unavailable"
_FALLBACK_PARSE_ERROR = "parse_error"
_FALLBACK_EVIDENCE_ERROR = "evidence_build_error"
_FALLBACK_ROUTER_ERROR = "skill_router_error"
_FALLBACK_JUDGE_ERROR = "judge_error"
_FALLBACK_NO_FINAL_RESULT = "no_final_result"


class SkillRouterEngine(Protocol):
    def plan(
        self,
        *,
        evidence_pack: Any,
        has_content: bool,
        can_call_remote: bool,
        pipeline_policy: Any | None = None,
    ) -> Any: ...


def _minimal_email_input(text: str) -> EmailInput:
    return EmailInput(text=str(text or ""))


def _minimal_evidence_pack() -> EvidencePack:
    return EvidencePack.model_validate(
        {
            "email_meta": {"message_id": "fallback"},
            "header_signals": {},
            "pre_score": {
                "risk_score": 35,
                "route": "review",
                "reasons": ["runtime:fallback"],
            },
        }
    )


def _minimal_precheck(email: Any) -> dict[str, Any]:
    raw_urls = getattr(email, "urls", [])
    urls = [str(item).strip() for item in raw_urls if isinstance(item, str) and str(item).strip()]
    return {
        "chain_flags": [],
        "combined_urls": list(dict.fromkeys(urls)),
        "indicators": ["runtime:fallback"],
    }


def _reason_with_error(reason_code: str, error: Exception | None) -> str:
    if error is None:
        return reason_code
    return f"{reason_code}:{type(error).__name__}"


@dataclass
class PipelineExecutor:
    parse_input: ParseInputFn
    evidence_builder: EvidenceBuilder
    skill_router: SkillRouterEngine
    judge: JudgeEngine
    fallback_builder: FallbackFn

    def _build_emergency_result(
        self,
        *,
        service: PipelineRuntime,
        email: Any,
        precheck: dict[str, Any],
        fallback_reason: str,
        error: Exception | None = None,
    ) -> dict[str, Any]:
        combined_urls = precheck.get("combined_urls", []) if isinstance(precheck, dict) else []
        urls = [
            str(item).strip()
            for item in combined_urls
            if isinstance(item, str) and str(item).strip()
        ]
        attachments = getattr(email, "attachments", [])
        safe_attachments = [str(item) for item in attachments] if isinstance(attachments, list) else []

        evidence_error = type(error).__name__ if error is not None else ""
        return {
            "verdict": "phishing",
            "reason": "Deterministic fallback failed; emergency response emitted.",
            "path": "STANDARD",
            "risk_score": 35,
            "confidence": 0.35,
            "email_label": "phish_email",
            "is_spam": False,
            "is_phish_email": True,
            "spam_score": 8,
            "threat_tags": ["fallback-error"],
            "indicators": ["runtime:fallback_emergency"],
            "recommended_actions": [
                "Do not click unknown links",
                "Escalate to analyst review before user interaction",
            ],
            "input": str(getattr(email, "text", "")),
            "urls": urls,
            "attachments": safe_attachments,
            "provider_used": f"{service.provider}:fallback",
            "evidence": {
                "error": evidence_error,
                "precheck": precheck if isinstance(precheck, dict) else {},
            },
            "precheck": precheck if isinstance(precheck, dict) else {},
            "fallback_reason": fallback_reason,
        }

    def _build_fallback_result(
        self,
        *,
        service: PipelineRuntime,
        email: Any,
        evidence_pack: Any,
        precheck: dict[str, Any],
        reason_code: str,
        error: Exception | None = None,
    ) -> dict[str, Any]:
        fallback_reason = _reason_with_error(reason_code, error)
        try:
            fallback_output = self.fallback_builder(
                email,
                service.provider,
                evidence_pack,
                precheck,
                pipeline_policy=service.pipeline_policy,
            )
            if hasattr(fallback_output, "model_dump"):
                final = fallback_output.model_dump(mode="json")
            elif isinstance(fallback_output, dict):
                final = dict(fallback_output)
            else:
                raise TypeError("Unsupported fallback output type.")
            if not isinstance(final, dict):
                raise TypeError("Fallback output must be dict-like.")
            final["precheck"] = precheck
            final["fallback_reason"] = fallback_reason
            return final
        except Exception as fallback_exc:
            emergency_reason = f"{fallback_reason}:fallback_builder_error:{type(fallback_exc).__name__}"
            return self._build_emergency_result(
                service=service,
                email=email,
                precheck=precheck,
                fallback_reason=emergency_reason,
                error=error or fallback_exc,
            )

    def analyze_stream(self, *, service: PipelineRuntime, text: str) -> Generator[dict[str, Any], None, None]:
        email: Any = _minimal_email_input(text)
        evidence_pack: Any = _minimal_evidence_pack()
        precheck: dict[str, Any] = _minimal_precheck(email)

        try:
            email = self.parse_input(text)
            precheck = _minimal_precheck(email)
        except Exception as exc:
            final = self._build_fallback_result(
                service=service,
                email=email,
                evidence_pack=evidence_pack,
                precheck=precheck,
                reason_code=_FALLBACK_PARSE_ERROR,
                error=exc,
            )
            yield service.event("runtime", "error", f"Input parse failed: {type(exc).__name__}. Using fallback.")
            yield {"type": "final", "result": final}
            return

        try:
            evidence_pack, precheck = self.evidence_builder.build(email, service)
        except Exception as exc:
            final = self._build_fallback_result(
                service=service,
                email=email,
                evidence_pack=evidence_pack,
                precheck=precheck,
                reason_code=_FALLBACK_EVIDENCE_ERROR,
                error=exc,
            )
            yield service.event(
                "runtime",
                "error",
                f"Evidence build failed: {type(exc).__name__}. Using fallback.",
            )
            yield {"type": "final", "result": final}
            return

        has_content = bool(email.text or email.urls or email.attachments)
        try:
            plan = self.skill_router.plan(
                evidence_pack=evidence_pack,
                has_content=has_content,
                can_call_remote=service.can_call_remote(),
                pipeline_policy=service.pipeline_policy,
            )
        except Exception as exc:
            final = self._build_fallback_result(
                service=service,
                email=email,
                evidence_pack=evidence_pack,
                precheck=precheck,
                reason_code=_FALLBACK_ROUTER_ERROR,
                error=exc,
            )
            yield service.event(
                "runtime",
                "error",
                f"Skill routing failed: {type(exc).__name__}. Using fallback.",
            )
            yield {"type": "final", "result": final}
            return

        if not plan.has_content:
            final = self._build_fallback_result(
                service=service,
                email=email,
                evidence_pack=evidence_pack,
                precheck=precheck,
                reason_code=_FALLBACK_EMPTY_INPUT,
            )
            yield service.event("init", "done", "Input empty; return fallback result.")
            yield {"type": "final", "result": final}
            return

        yield service.event(
            "init",
            "done",
            "Input parsed.",
            data={
                "text_len": len(email.text),
                "url_count": len(precheck.get("combined_urls", [])),
                "attachment_count": len(email.attachments),
                "chain_flags": precheck.get("chain_flags", []),
            },
        )
        yield service.event(
            "header_intel",
            "done",
            "Header analysis completed.",
            data={
                "from_replyto_mismatch": evidence_pack.header_signals.from_replyto_mismatch,
                "received_hops": evidence_pack.header_signals.received_hops,
                "confidence": evidence_pack.header_signals.confidence,
            },
        )
        yield service.event(
            "url_intel",
            "done",
            "URL analysis completed.",
            data={
                "url_count": len(evidence_pack.url_signals),
                "suspicious_url_count": len(precheck.get("suspicious_urls", [])),
            },
        )
        yield service.event(
            "pre_score",
            "done",
            "Deterministic pre-score ready.",
            data=evidence_pack.pre_score.model_dump(mode="json"),
        )
        yield service.event(
            "skill_router",
            "done",
            "Skill router generated execution plan.",
            data={
                "route": plan.route,
                "path": plan.path,
                "should_invoke_judge": plan.should_invoke_judge,
                "reasons": plan.reasons[:4],
            },
        )

        if evidence_pack.web_signals or precheck.get("attachment_reports"):
            context_decisions = precheck.get("context_decisions", {})
            web_decision = context_decisions.get("web", {}) if isinstance(context_decisions, dict) else {}
            attachment_decision = context_decisions.get("attachment", {}) if isinstance(context_decisions, dict) else {}
            yield service.event(
                "deep_context",
                "done",
                "Conditional web/attachment context collected.",
                data={
                    "web_signals": len(evidence_pack.web_signals),
                    "attachment_reports": len(precheck.get("attachment_reports", [])),
                    "web_reason": str(web_decision.get("reason", "")),
                    "attachment_reason": str(attachment_decision.get("reason", "")),
                },
            )

        if not plan.should_invoke_judge:
            final = self._build_fallback_result(
                service=service,
                email=email,
                evidence_pack=evidence_pack,
                precheck=precheck,
                reason_code=_FALLBACK_REMOTE_UNAVAILABLE,
            )
            yield service.event("runtime", "fallback", "Remote model unavailable; using deterministic fallback.")
            yield {"type": "final", "result": final}
            return

        yield service.event("judge", "running", "Judge agent is evaluating the evidence pack.")
        try:
            fallback_for_judge = self.fallback_builder(
                email,
                service.provider,
                evidence_pack,
                precheck,
                pipeline_policy=service.pipeline_policy,
            )
        except Exception:
            fallback_for_judge = SimpleNamespace(recommended_actions=[], reason="")
        judge_result = self.judge.evaluate(
            service=service,
            email=email,
            evidence_pack=evidence_pack,
            precheck=precheck,
            fallback=fallback_for_judge,
        )
        if judge_result.error is not None or judge_result.final_result is None:
            final = self._build_fallback_result(
                service=service,
                email=email,
                evidence_pack=evidence_pack,
                precheck=precheck,
                reason_code=_FALLBACK_JUDGE_ERROR,
                error=judge_result.error,
            )
            err_name = type(judge_result.error).__name__ if judge_result.error is not None else "UnknownError"
            yield service.event("runtime", "error", f"Judge failed: {err_name}. Use fallback.")
            yield {"type": "final", "result": final}
            return

        judge_output = judge_result.judge_output
        if judge_output is not None:
            yield service.event(
                "judge",
                "done",
                "Judge completed.",
                data={
                    "verdict": judge_output.verdict,
                    "risk_score": judge_output.risk_score,
                    "confidence": judge_output.confidence,
                    "top_evidence": len(judge_output.top_evidence),
                },
            )
        yield service.event("judge", "done", "Final verdict ready.")
        yield {"type": "final", "result": judge_result.final_result}

    def analyze(self, *, service: PipelineRuntime, text: str) -> dict[str, Any]:
        final: dict[str, Any] | None = None
        for event in self.analyze_stream(service=service, text=text):
            if event.get("type") == "final":
                result = event.get("result")
                if isinstance(result, dict):
                    final = result
        if final is not None:
            return final
        email = _minimal_email_input(text)
        return self._build_emergency_result(
            service=service,
            email=email,
            precheck=_minimal_precheck(email),
            fallback_reason=_FALLBACK_NO_FINAL_RESULT,
        )
