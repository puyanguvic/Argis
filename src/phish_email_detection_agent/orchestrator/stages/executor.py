"""Executor stage orchestrating skill routing, evidence, and judge flow."""

from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import Any, Protocol

from phish_email_detection_agent.orchestrator.stages.evidence_builder import EvidenceBuilder
from phish_email_detection_agent.orchestrator.stages.judge import JudgeEngine
from phish_email_detection_agent.orchestrator.stages.runtime import PipelineRuntime


ParseInputFn = Callable[[str], Any]
FallbackFn = Callable[..., Any]


class SkillRouterEngine(Protocol):
    def plan(
        self,
        *,
        evidence_pack: Any,
        has_content: bool,
        can_call_remote: bool,
        pipeline_policy: Any | None = None,
    ) -> Any: ...


@dataclass
class PipelineExecutor:
    parse_input: ParseInputFn
    evidence_builder: EvidenceBuilder
    skill_router: SkillRouterEngine
    judge: JudgeEngine
    fallback_builder: FallbackFn

    def analyze_stream(self, *, service: PipelineRuntime, text: str) -> Generator[dict[str, Any], None, None]:
        email = self.parse_input(text)
        evidence_pack, precheck = self.evidence_builder.build(email, service)
        fallback = self.fallback_builder(
            email,
            service.provider,
            evidence_pack,
            precheck,
            pipeline_policy=service.pipeline_policy,
        )
        has_content = bool(email.text or email.urls or email.attachments)
        plan = self.skill_router.plan(
            evidence_pack=evidence_pack,
            has_content=has_content,
            can_call_remote=service.can_call_remote(),
            pipeline_policy=service.pipeline_policy,
        )

        if not plan.has_content:
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
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
            yield service.event(
                "deep_context",
                "done",
                "Conditional web/attachment context collected.",
                data={
                    "web_signals": len(evidence_pack.web_signals),
                    "attachment_reports": len(precheck.get("attachment_reports", [])),
                },
            )

        if not plan.should_invoke_judge:
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
            yield service.event("runtime", "fallback", "Remote model unavailable; using deterministic fallback.")
            yield {"type": "final", "result": final}
            return

        yield service.event("judge", "running", "Judge agent is evaluating the evidence pack.")
        judge_result = self.judge.evaluate(
            service=service,
            email=email,
            evidence_pack=evidence_pack,
            precheck=precheck,
            fallback=fallback,
        )
        if judge_result.error is not None or judge_result.final_result is None:
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
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
        email = self.parse_input(text)
        evidence_pack, precheck = self.evidence_builder.build(email, service)
        return self.fallback_builder(
            email,
            service.provider,
            evidence_pack,
            precheck,
            pipeline_policy=service.pipeline_policy,
        ).model_dump(mode="json")
