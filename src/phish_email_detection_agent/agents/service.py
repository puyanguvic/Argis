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
from phish_email_detection_agent.agents.risk_fusion import fuse_risk_scores
from phish_email_detection_agent.agents.router import route_text
from phish_email_detection_agent.agents.tool_registry import ToolRegistry
from phish_email_detection_agent.tools.attachment_analysis import AttachmentPolicy, analyze_attachments
from phish_email_detection_agent.tools.domain_intel import analyze_domain
from phish_email_detection_agent.tools.email import extract_urls, is_suspicious_url
from phish_email_detection_agent.tools.preprocessing import (
    extract_urls_from_html,
    parse_input_payload,
    summarize_chain_flags,
)
from phish_email_detection_agent.tools.text import contains_phishing_keywords
from phish_email_detection_agent.tools.url_analysis import SafeFetchPolicy, analyze_url_target

TraceEvent = dict[str, Any]


def _extract_keywords(text: str) -> list[str]:
    raw = (text or "").lower()
    keywords = (
        "verify",
        "password",
        "urgent",
        "invoice",
        "wire transfer",
        "login",
        "security",
        "suspended",
        "mfa",
    )
    return [item for item in keywords if item in raw]


def _build_safe_fetch_policy(service: "AgentService") -> SafeFetchPolicy:
    return SafeFetchPolicy(
        enabled=service.enable_url_fetch,
        timeout_s=service.fetch_timeout_s,
        max_redirects=service.fetch_max_redirects,
        max_bytes=service.fetch_max_bytes,
        allow_private_network=service.allow_private_network,
        sandbox_backend=service.url_fetch_backend,
        sandbox_exec_timeout_s=service.url_sandbox_exec_timeout_s,
        firejail_bin=service.url_firejail_bin,
        docker_bin=service.url_docker_bin,
        docker_image=service.url_docker_image,
    )


def _build_attachment_policy(service: "AgentService") -> AttachmentPolicy:
    return AttachmentPolicy(
        max_read_bytes=service.attachment_max_read_bytes,
        enable_ocr=service.enable_ocr,
        ocr_backend=service.ocr_backend,
        ocr_languages=service.ocr_languages,
        enable_qr_decode=service.enable_qr_decode,
        enable_audio_transcription=service.enable_audio_transcription,
        audio_backend=service.audio_transcription_backend,
        audio_model=service.audio_transcription_model,
        audio_local_model_size=service.audio_local_model_size,
        whisper_cli_path=service.whisper_cli_path,
        openai_api_key=service.audio_openai_api_key or service.api_key,
        openai_base_url=service.audio_openai_base_url or service.api_base,
    )


def _local_artifact_precheck(email: EmailInput, service: "AgentService") -> dict[str, Any]:
    """Deterministic artifact checks for trace visibility and fallback support."""

    combined_urls = list(
        dict.fromkeys(email.urls + extract_urls(email.text) + extract_urls(email.body_text))
    )
    html_url_meta = extract_urls_from_html(email.body_html or "")
    combined_urls = list(dict.fromkeys(combined_urls + html_url_meta["urls"]))
    chain_flags = summarize_chain_flags(email)
    if html_url_meta["hidden_links"]:
        chain_flags.append("hidden_html_links")

    safe_fetch_policy = _build_safe_fetch_policy(service)
    attachment_policy = _build_attachment_policy(service)

    url_checks = [{"url": item, "suspicious": is_suspicious_url(item)} for item in combined_urls]
    url_target_reports = [analyze_url_target(item, policy=safe_fetch_policy) for item in combined_urls]
    domain_reports = [analyze_domain(item) for item in combined_urls]
    attachment_bundle = analyze_attachments(email.attachments, policy=attachment_policy)
    nested_urls = attachment_bundle.get("extracted_urls", [])

    if nested_urls:
        chain_flags.append("nested_url_in_attachment")
        combined_urls = list(dict.fromkeys(combined_urls + nested_urls))

    nested_domain_reports = [analyze_domain(item) for item in nested_urls]
    keyword_hits = _extract_keywords(" ".join([email.subject, email.text, email.body_text]))
    suspicious_urls = [item["url"] for item in url_checks if item["suspicious"]]
    suspicious_urls.extend(
        item["url"] for item in url_target_reports if int(item.get("risk_score", 0)) >= 50
    )
    suspicious_urls.extend(
        item["url"] for item in domain_reports if int(item.get("risk_score", 0)) >= 45
    )
    suspicious_urls = list(dict.fromkeys(suspicious_urls))
    risky_attachments = [name for name in attachment_bundle.get("risky", []) if isinstance(name, str)]

    text_score = min(
        100,
        len(keyword_hits) * 10 + (15 if contains_phishing_keywords(email.text) else 0),
    )
    shortener_bonus = min(
        20,
        sum(
            10
            for item in combined_urls
            if any(token in item.lower() for token in ("bit.ly/", "tinyurl.com/", "t.co/", "rb.gy/"))
        ),
    )
    chain_bonus = 20 if combined_urls and email.attachments else 0
    url_signal_score = (
        len(suspicious_urls) * 16
        + min(40, len(html_url_meta["hidden_links"]) * 18)
        + max([int(item.get("risk_score", 0)) for item in url_target_reports], default=0) // 2
        + shortener_bonus
        + chain_bonus
    )
    url_score = min(
        100,
        url_signal_score,
    )
    domain_scores = [int(item.get("risk_score", 0)) for item in (domain_reports + nested_domain_reports)]
    domain_score = int(round(sum(domain_scores) / len(domain_scores))) if domain_scores else 0
    attachment_scores = [
        int(item.get("risk_score", 0)) for item in attachment_bundle.get("reports", []) if isinstance(item, dict)
    ]
    attachment_score = max(attachment_scores, default=0)
    image_ocr_scores = [
        int(item.get("details", {}).get("risk_score", 0))
        for item in attachment_bundle.get("reports", [])
        if isinstance(item, dict) and item.get("type") == "image"
    ]
    ocr_score = max(image_ocr_scores, default=0)
    fusion = fuse_risk_scores(
        text_score=text_score,
        url_score=url_score,
        domain_score=domain_score,
        attachment_score=attachment_score,
        ocr_score=ocr_score,
    )

    indicators: list[str] = []
    indicators.extend([f"keyword:{item}" for item in keyword_hits])
    indicators.extend([f"url:{item}" for item in suspicious_urls])
    indicators.extend([f"attachment:{item}" for item in risky_attachments])
    indicators.extend([f"chain:{item}" for item in chain_flags])

    attachment_checks = [
        {"name": item.get("name", ""), "risk_score": item.get("risk_score", 0), "type": item.get("type", "")}
        for item in attachment_bundle.get("reports", [])
        if isinstance(item, dict)
    ]

    return {
        "chain_flags": list(dict.fromkeys(chain_flags)),
        "hidden_links": html_url_meta["hidden_links"],
        "combined_urls": combined_urls,
        "url_checks": url_checks,
        "url_target_reports": url_target_reports,
        "domain_reports": domain_reports + nested_domain_reports,
        "attachment_checks": attachment_checks,
        "attachment_reports": attachment_bundle.get("reports", []),
        "attachment_extracted_urls": nested_urls,
        "keyword_hits": keyword_hits,
        "suspicious_urls": suspicious_urls,
        "risky_attachments": risky_attachments,
        "indicators": list(dict.fromkeys(indicators)),
        "component_scores": {
            "text": text_score,
            "url": url_score,
            "domain": domain_score,
            "attachment": attachment_score,
            "ocr": ocr_score,
        },
        "heuristic_score": fusion["risk_score"],
        "fusion": fusion,
        "fetch_policy": {
            "enabled": safe_fetch_policy.enabled,
            "backend": safe_fetch_policy.sandbox_backend,
            "allow_private_network": safe_fetch_policy.allow_private_network,
            "max_bytes": safe_fetch_policy.max_bytes,
            "max_redirects": safe_fetch_policy.max_redirects,
        },
    }


def _fallback_result(email: EmailInput, provider: str, precheck: dict[str, Any]) -> TriageResult:
    score = int(precheck.get("fusion", {}).get("risk_score", 0))
    phishing = precheck.get("fusion", {}).get("verdict") == "phishing"
    has_chain = bool(precheck.get("chain_flags"))
    if phishing:
        reason = "multi-signal attack-chain risk detected"
    elif has_chain and score >= 35:
        reason = "suspicious chain pattern detected, monitor carefully"
    else:
        reason = "no strong phishing evidence"

    actions = [
        "Do not click unknown links",
        "Verify sender through trusted channel",
    ]
    if has_chain:
        actions.append("Review full attack chain evidence before user interaction")
    if phishing:
        actions.append("Escalate to security team for deep review")

    return TriageResult(
        verdict="phishing" if phishing else "benign",
        reason=reason,
        path=route_text(" ".join([email.subject, email.text, email.body_text])),
        risk_score=score,
        indicators=list(precheck.get("indicators", [])),
        recommended_actions=list(dict.fromkeys(actions)),
        input=email.text,
        urls=list(precheck.get("combined_urls", [])),
        attachments=email.attachments,
        provider_used=f"{provider}:fallback",
        evidence={
            "chain_flags": precheck.get("chain_flags", []),
            "component_scores": precheck.get("component_scores", {}),
            "url_reports": precheck.get("url_target_reports", []),
            "domain_reports": precheck.get("domain_reports", []),
            "attachment_reports": precheck.get("attachment_reports", []),
        },
    )


@dataclass
class AgentService:
    provider: str
    model: str
    temperature: float = 0.0
    api_base: str | None = None
    api_key: str | None = None
    max_turns: int = 8
    enable_url_fetch: bool = False
    fetch_timeout_s: float = 5.0
    fetch_max_redirects: int = 4
    fetch_max_bytes: int = 1_000_000
    allow_private_network: bool = False
    url_fetch_backend: str = "internal"
    url_sandbox_exec_timeout_s: float = 20.0
    url_firejail_bin: str = "firejail"
    url_docker_bin: str = "docker"
    url_docker_image: str = "python:3.11-slim"
    attachment_max_read_bytes: int = 4_000_000
    enable_ocr: bool = False
    ocr_backend: str = "tesseract"
    ocr_languages: str = "eng"
    enable_qr_decode: bool = True
    enable_audio_transcription: bool = False
    audio_transcription_backend: str = "openai"
    audio_transcription_model: str = "gpt-4o-mini-transcribe"
    audio_local_model_size: str = "small"
    whisper_cli_path: str = "whisper"
    audio_openai_api_key: str | None = None
    audio_openai_base_url: str | None = None

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
        email = parse_input_payload(text)
        precheck = _local_artifact_precheck(email, self)
        fallback = _fallback_result(email, self.provider, precheck)

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
                "chain_flags": precheck["chain_flags"],
            },
        )

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
        for item in precheck["domain_reports"]:
            yield self._event("tool.domain_check", "done", "Domain intelligence completed.", data=item)
        yield self._event(
            "tool.precheck",
            "done",
            "Artifact precheck summary ready.",
            data={
                "heuristic_score": precheck["heuristic_score"],
                "suspicious_urls": len(precheck["suspicious_urls"]),
                "risky_attachments": len(precheck["risky_attachments"]),
                "component_scores": precheck["component_scores"],
                "url_fetch_enabled": self.enable_url_fetch,
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
                chain_signals=[],
                artifact_reports={},
                risk_score=0,
                summary="No deep investigation executed.",
            )

            should_investigate = router_output.needs_deep or router_output.path in {"STANDARD", "DEEP"}
            if should_investigate:
                yield self._event("investigator", "running", "Investigator agent is analyzing artifacts.")
                investigation_payload = {
                    "email": router_input,
                    "router": router_output.model_dump(mode="json"),
                    "precheck": precheck,
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
                        "chain_signals": report.chain_signals,
                    },
                )
            else:
                yield self._event("investigator", "skipped", "Investigation skipped by router decision.")

            yield self._event("summarizer", "running", "Summarizer agent is producing final verdict.")
            summary_payload = {
                "email": router_input,
                "router": router_output.model_dump(mode="json"),
                "investigation": report.model_dump(mode="json"),
                "precheck": precheck,
            }
            sum_run = Runner.run_sync(
                summarizer_agent,
                json.dumps(summary_payload, ensure_ascii=True),
                max_turns=self.max_turns,
            )
            final_output = TriageOutput.model_validate(getattr(sum_run, "final_output", {}))
            final_output.path = router_output.path

            deterministic_score = int(precheck.get("fusion", {}).get("risk_score", 0))
            deterministic_verdict = str(precheck.get("fusion", {}).get("verdict", "benign"))
            merged_score = max(final_output.risk_score, deterministic_score)
            merged_verdict = final_output.verdict
            if deterministic_verdict == "phishing" and merged_score >= 35:
                merged_verdict = "phishing"

            merged_indicators = list(dict.fromkeys(final_output.indicators + precheck["indicators"]))
            merged_actions = list(
                dict.fromkeys(
                    final_output.recommended_actions
                    + [
                        "Do not click unknown links",
                        "Verify sender through trusted channel",
                    ]
                )
            )

            final = TriageResult(
                verdict=merged_verdict,
                reason=final_output.reason.strip(),
                path=final_output.path,
                risk_score=merged_score,
                indicators=merged_indicators,
                recommended_actions=merged_actions,
                input=email.text,
                urls=precheck["combined_urls"],
                attachments=email.attachments,
                provider_used=self.provider,
                evidence={
                    "precheck": precheck,
                    "investigation": report.model_dump(mode="json"),
                    "deterministic_fusion": precheck["fusion"],
                },
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
        if final:
            return final
        email = parse_input_payload(text)
        precheck = _local_artifact_precheck(email, self)
        return _fallback_result(email, self.provider, precheck).model_dump(mode="json")
