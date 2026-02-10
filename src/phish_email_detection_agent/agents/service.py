"""Professional multi-agent service built on OpenAI Agents SDK."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
import importlib.util
import json
import os
from typing import Any

from phish_email_detection_agent.agents.contracts import (
    EmailInput,
    InvestigationReport,
    RouterDecision,
    TriageOutput,
    TriageResult,
)
from phish_email_detection_agent.agents.prompts import INVESTIGATOR_PROMPT, ROUTER_PROMPT, SUMMARIZER_PROMPT
from phish_email_detection_agent.agents.providers import ProviderConfig, build_model_reference
from phish_email_detection_agent.agents.router import route_text
from phish_email_detection_agent.agents.tool_registry import ToolRegistry
from phish_email_detection_agent.tools.email import classify_attachment, extract_urls, is_suspicious_url
from phish_email_detection_agent.tools.text import contains_phishing_keywords, normalize_text

TraceEvent = dict[str, Any]


def _extract_keywords(text: str) -> list[str]:
    raw = (text or "").lower()
    keywords = ("verify", "password", "urgent", "invoice", "wire transfer", "login", "security")
    return [item for item in keywords if item in raw]


def _parse_email_input(raw: str) -> EmailInput:
    clean = normalize_text(raw)
    if not clean:
        return EmailInput()

    if clean.startswith("{") and clean.endswith("}"):
        try:
            payload = json.loads(clean)
            return EmailInput.model_validate(payload)
        except Exception:
            pass

    return EmailInput(text=clean)


def _fallback_result(email: EmailInput, provider: str) -> TriageResult:
    combined_urls = list(dict.fromkeys(email.urls + extract_urls(email.text)))
    suspicious_urls = [item for item in combined_urls if is_suspicious_url(item)]
    risky_attachments = [
        name for name in email.attachments if classify_attachment(name) in {"high_risk", "macro_risk"}
    ]
    keyword_hits = _extract_keywords(email.text)

    score = min(100, len(keyword_hits) * 12 + len(suspicious_urls) * 25 + len(risky_attachments) * 25)
    phishing = score >= 35 or contains_phishing_keywords(email.text)

    indicators: list[str] = []
    indicators.extend([f"keyword:{item}" for item in keyword_hits])
    indicators.extend([f"url:{item}" for item in suspicious_urls])
    indicators.extend([f"attachment:{item}" for item in risky_attachments])

    actions = [
        "Do not click unknown links",
        "Verify sender through trusted channel",
    ]
    if phishing:
        actions.append("Escalate to security team for deep review")

    return TriageResult(
        verdict="phishing" if phishing else "benign",
        reason="multi-signal risk detected" if phishing else "no strong phishing evidence",
        path=route_text(email.text),
        risk_score=score,
        indicators=indicators,
        recommended_actions=actions,
        input=email.text,
        urls=combined_urls,
        attachments=email.attachments,
        provider_used=f"{provider}:fallback",
    )


def _local_artifact_precheck(email: EmailInput) -> dict[str, Any]:
    """Deterministic artifact checks for trace visibility and fallback support."""

    combined_urls = list(dict.fromkeys(email.urls + extract_urls(email.text)))
    url_checks = [{"url": item, "suspicious": is_suspicious_url(item)} for item in combined_urls]
    attachment_checks = [{"name": item, "risk": classify_attachment(item)} for item in email.attachments]
    keyword_hits = _extract_keywords(email.text)
    suspicious_urls = [item["url"] for item in url_checks if item["suspicious"]]
    risky_attachments = [
        item["name"] for item in attachment_checks if item["risk"] in {"high_risk", "macro_risk"}
    ]
    heuristic_score = min(
        100,
        len(keyword_hits) * 12 + len(suspicious_urls) * 25 + len(risky_attachments) * 25,
    )
    return {
        "combined_urls": combined_urls,
        "url_checks": url_checks,
        "attachment_checks": attachment_checks,
        "keyword_hits": keyword_hits,
        "suspicious_urls": suspicious_urls,
        "risky_attachments": risky_attachments,
        "heuristic_score": heuristic_score,
    }


@dataclass
class AgentService:
    provider: str
    model: str
    temperature: float = 0.0
    api_base: str | None = None
    api_key: str | None = None
    max_turns: int = 8

    def _can_call_remote(self) -> bool:
        if importlib.util.find_spec("agents") is None:
            return False
        if self.provider == "openai":
            return bool(self.api_key or os.getenv("OPENAI_API_KEY"))
        return True

    def _build_common_kwargs(self) -> dict[str, object]:
        from agents import ModelSettings

        registry = ToolRegistry()
        registry.register_all()
        model_ref = build_model_reference(
            ProviderConfig(
                provider=self.provider,
                model=self.model,
                api_base=self.api_base,
                api_key=self.api_key,
            )
        )
        return {
            "model": model_ref,
            "tools": registry.export(),
            "model_settings": ModelSettings(temperature=self.temperature),
        }

    def _event(self, stage: str, status: str, message: str, data: dict[str, Any] | None = None) -> TraceEvent:
        payload: TraceEvent = {
            "stage": stage,
            "status": status,
            "message": message,
        }
        if data:
            payload["data"] = data
        return payload

    def analyze_stream(self, text: str) -> Generator[TraceEvent, None, None]:
        email = _parse_email_input(text)
        fallback = _fallback_result(email, self.provider)

        if not email.text and not email.urls and not email.attachments:
            final = fallback.model_dump(mode="json")
            yield self._event("init", "done", "Input empty; return fallback result.")
            yield {"type": "final", "result": final}
            return

        yield self._event(
            "init",
            "done",
            "Input parsed.",
            data={
                "text_len": len(email.text),
                "url_count": len(email.urls),
                "attachment_count": len(email.attachments),
            },
        )

        # Tool-level trace: deterministic prechecks for each artifact.
        precheck = _local_artifact_precheck(email)
        yield self._event(
            "tool.keyword_scan",
            "done",
            "Keyword scan completed.",
            data={"hits": precheck["keyword_hits"], "count": len(precheck["keyword_hits"])},
        )
        for item in precheck["url_checks"]:
            yield self._event(
                "tool.url_check",
                "done",
                "URL risk check completed.",
                data=item,
            )
        for item in precheck["attachment_checks"]:
            yield self._event(
                "tool.attachment_check",
                "done",
                "Attachment risk check completed.",
                data=item,
            )
        yield self._event(
            "tool.precheck",
            "done",
            "Artifact precheck summary ready.",
            data={
                "heuristic_score": precheck["heuristic_score"],
                "suspicious_urls": len(precheck["suspicious_urls"]),
                "risky_attachments": len(precheck["risky_attachments"]),
            },
        )

        if not self._can_call_remote():
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
            yield self._event("runtime", "fallback", "Remote model unavailable; using deterministic fallback.")
            yield {"type": "final", "result": final}
            return

        try:
            from agents import Agent, Runner

            common = self._build_common_kwargs()
            router_agent = Agent(
                name="argis-router-agent",
                instructions=ROUTER_PROMPT,
                output_type=RouterDecision,
                **common,
            )
            investigator_agent = Agent(
                name="argis-investigator-agent",
                instructions=INVESTIGATOR_PROMPT,
                output_type=InvestigationReport,
                **common,
            )
            summarizer_agent = Agent(
                name="argis-summarizer-agent",
                instructions=SUMMARIZER_PROMPT,
                output_type=TriageOutput,
                **common,
            )

            router_input = email.model_dump(mode="json")
            yield self._event("router", "running", "Router agent is deciding depth path.")
            router_run = Runner.run_sync(
                router_agent,
                json.dumps(router_input, ensure_ascii=True),
                max_turns=self.max_turns,
            )
            router_output = RouterDecision.model_validate(getattr(router_run, "final_output", {}))
            yield self._event(
                "router",
                "done",
                "Router completed.",
                data={
                    "path": router_output.path,
                    "needs_deep": router_output.needs_deep,
                    "rationale": router_output.rationale,
                },
            )

            report = InvestigationReport(
                suspicious_urls=[],
                risky_attachments=[],
                keyword_hits=[],
                risk_score=0,
                summary="No deep investigation executed.",
            )

            should_investigate = router_output.needs_deep or router_output.path in {"STANDARD", "DEEP"}
            if should_investigate:
                yield self._event("investigator", "running", "Investigator agent is analyzing artifacts.")
                investigation_payload = {
                    "email": router_input,
                    "router": router_output.model_dump(mode="json"),
                }
                inv_run = Runner.run_sync(
                    investigator_agent,
                    json.dumps(investigation_payload, ensure_ascii=True),
                    max_turns=self.max_turns,
                )
                report = InvestigationReport.model_validate(getattr(inv_run, "final_output", {}))
                yield self._event(
                    "investigator",
                    "done",
                    "Investigator completed.",
                    data={
                        "risk_score": report.risk_score,
                        "suspicious_urls": len(report.suspicious_urls),
                        "risky_attachments": len(report.risky_attachments),
                    },
                )
            else:
                yield self._event("investigator", "skipped", "Investigation skipped by router decision.")

            yield self._event("summarizer", "running", "Summarizer agent is producing final verdict.")
            summary_payload = {
                "email": router_input,
                "router": router_output.model_dump(mode="json"),
                "investigation": report.model_dump(mode="json"),
            }
            sum_run = Runner.run_sync(
                summarizer_agent,
                json.dumps(summary_payload, ensure_ascii=True),
                max_turns=self.max_turns,
            )
            final_output = TriageOutput.model_validate(getattr(sum_run, "final_output", {}))
            final_output.path = router_output.path

            final = TriageResult(
                verdict=final_output.verdict,
                reason=final_output.reason.strip(),
                path=final_output.path,
                risk_score=final_output.risk_score,
                indicators=final_output.indicators,
                recommended_actions=final_output.recommended_actions,
                input=email.text,
                urls=list(dict.fromkeys(email.urls + extract_urls(email.text))),
                attachments=email.attachments,
                provider_used=self.provider,
            ).model_dump(mode="json")
            final["precheck"] = precheck

            yield self._event("summarizer", "done", "Final verdict ready.")
            yield {"type": "final", "result": final}
        except Exception as exc:
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
            yield self._event("runtime", "error", f"Agent pipeline failed: {type(exc).__name__}. Use fallback.")
            yield {"type": "final", "result": final}

    def analyze(self, text: str) -> dict[str, object]:
        final: dict[str, Any] | None = None
        for event in self.analyze_stream(text):
            if event.get("type") == "final":
                result = event.get("result")
                if isinstance(result, dict):
                    final = result
        return final or _fallback_result(_parse_email_input(text), self.provider).model_dump(mode="json")
