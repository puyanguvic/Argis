"""Evidence-pack phishing pipeline built on OpenAI Agents SDK."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
import importlib.util
import os
from typing import Any

from phish_email_detection_agent.orchestrator.contracts import (
    EmailInput,
    EvidencePack,
    TriageResult,
)
from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy
from phish_email_detection_agent.orchestrator.stages.evidence_builder import EvidenceBuilder
from phish_email_detection_agent.orchestrator.stages.evidence_stage import EvidenceStage
from phish_email_detection_agent.orchestrator.stages.executor import PipelineExecutor
from phish_email_detection_agent.orchestrator.stages.judge import JudgeEngine
from phish_email_detection_agent.orchestrator.verdict_routing import (
    compute_confidence as _verdict_compute_confidence,
    map_route_to_path as _verdict_map_route_to_path,
    merge_judge_verdict as _verdict_merge_judge_verdict,
    normalize_score_for_verdict as _verdict_normalize_score_for_verdict,
    verdict_from_score as _verdict_score_to_label,
)
from phish_email_detection_agent.orchestrator.precheck import (
    build_attachment_signals as _build_attachment_signals,
    build_nlp_cues as _build_nlp_cues,
    build_web_signals as _build_web_signals,
    clip_score as _clip_score,
    compute_pre_score as _compute_pre_score,
    enrich_attachments_with_static_scan as _enrich_attachments_with_static_scan,
    infer_url_signals as _infer_url_signals,
    should_collect_deep_context as _should_collect_deep_context,
)
from phish_email_detection_agent.orchestrator.skill_router import SkillRouter
from phish_email_detection_agent.orchestrator.tracing import TraceEvent, make_event
from phish_email_detection_agent.providers.llm_openai import ProviderConfig, build_model_reference
from phish_email_detection_agent.tools.attachment.analyze import (
    AttachmentPolicy,
    analyze_attachments,
)
from phish_email_detection_agent.tools.intel.domain_intel import DomainIntelPolicy
from phish_email_detection_agent.tools.intel.header_intel import analyze_headers
from phish_email_detection_agent.domain.email.parse import (
    extract_urls_from_html,
    parse_input_payload,
    summarize_chain_flags,
)
from phish_email_detection_agent.domain.url.extract import extract_urls
from phish_email_detection_agent.tools.registry import ToolRegistry
from phish_email_detection_agent.tools.text.text_model import (
    derive_email_labels,
)
from phish_email_detection_agent.tools.url_fetch.service import SafeFetchPolicy

def _route_path(route: str) -> str:
    return _verdict_map_route_to_path(route)


def _verdict_from_score(score: int, *, suspicious_min_score: int, suspicious_max_score: int) -> str:
    return _verdict_score_to_label(
        score,
        suspicious_min_score=suspicious_min_score,
        suspicious_max_score=suspicious_max_score,
    )


def _normalize_score_for_verdict(
    score: int,
    verdict: str,
    *,
    suspicious_min_score: int,
    suspicious_max_score: int,
) -> int:
    return _verdict_normalize_score_for_verdict(
        score,
        verdict,
        suspicious_min_score=suspicious_min_score,
        suspicious_max_score=suspicious_max_score,
    )


def _merge_judge_verdict(
    *,
    deterministic_score: int,
    judge_verdict: str,
    judge_confidence: float,
    suspicious_min_score: int,
    suspicious_max_score: int,
) -> str:
    return _verdict_merge_judge_verdict(
        deterministic_score=deterministic_score,
        judge_verdict=judge_verdict,
        judge_confidence=judge_confidence,
        suspicious_min_score=suspicious_min_score,
        suspicious_max_score=suspicious_max_score,
    )


def _compute_confidence(*, score: int, verdict: str, judge_confidence: float, missing_count: int) -> float:
    return _verdict_compute_confidence(
        score=score,
        verdict=verdict,
        judge_confidence=judge_confidence,
        missing_count=missing_count,
    )


def _safe_fetch_policy(service: "AgentService") -> SafeFetchPolicy:
    return SafeFetchPolicy(
        enabled=service.enable_url_fetch,
        timeout_s=service.fetch_timeout_s,
        connect_timeout_s=min(service.fetch_timeout_s, service.fetch_connect_timeout_s),
        max_redirects=service.fetch_max_redirects,
        max_bytes=service.fetch_max_bytes,
        allow_private_network=service.allow_private_network,
        sandbox_backend=service.url_fetch_backend,
        sandbox_exec_timeout_s=service.url_sandbox_exec_timeout_s,
        firejail_bin=service.url_firejail_bin,
        docker_bin=service.url_docker_bin,
        docker_image=service.url_docker_image,
    )


def _attachment_policy(service: "AgentService") -> AttachmentPolicy:
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


def _domain_policy(service: "AgentService") -> DomainIntelPolicy:
    return DomainIntelPolicy(
        suspicious_token_cap=max(0, int(service.precheck_domain_token_cap)),
        synthetic_service_bonus=max(0, int(service.precheck_domain_synthetic_bonus)),
    )


_EVIDENCE_STAGE = EvidenceStage(
    extract_urls_from_html_fn=extract_urls_from_html,
    extract_urls_fn=extract_urls,
    summarize_chain_flags_fn=summarize_chain_flags,
    analyze_headers_fn=analyze_headers,
    safe_fetch_policy_fn=_safe_fetch_policy,
    attachment_policy_fn=_attachment_policy,
    domain_policy_fn=_domain_policy,
    infer_url_signals_fn=_infer_url_signals,
    build_nlp_cues_fn=_build_nlp_cues,
    build_attachment_signals_fn=_build_attachment_signals,
    compute_pre_score_fn=_compute_pre_score,
    should_collect_deep_context_fn=_should_collect_deep_context,
    build_web_signals_fn=_build_web_signals,
    analyze_attachments_fn=analyze_attachments,
    enrich_attachments_with_static_scan_fn=_enrich_attachments_with_static_scan,
    clip_score_fn=_clip_score,
)


def _build_evidence_pack(email: EmailInput, service: "AgentService") -> tuple[EvidencePack, dict[str, Any]]:
    return _EVIDENCE_STAGE.build(email, service)


def _fallback_result(
    email: EmailInput,
    provider: str,
    evidence_pack: EvidencePack,
    precheck: dict[str, Any],
    *,
    pipeline_policy: PipelinePolicy,
) -> TriageResult:
    policy = pipeline_policy.normalized()
    score = int(evidence_pack.pre_score.risk_score)
    verdict = _verdict_from_score(
        score,
        suspicious_min_score=policy.suspicious_min_score,
        suspicious_max_score=policy.suspicious_max_score,
    )
    if verdict == "suspicious":
        verdict = "phishing"
        score = max(35, score)
    route = str(evidence_pack.pre_score.route)

    if verdict == "phishing":
        reason = "Evidence pack indicates coordinated phishing signals."
    else:
        reason = "No strong phishing evidence detected in the current evidence pack."

    actions = [
        "Do not click unknown links",
        "Verify sender through trusted channel",
    ]
    if route in {"review", "deep"}:
        actions.append("Escalate to analyst review before user interaction")
    if verdict == "phishing":
        actions.append("Escalate to analyst review before user interaction")
    if verdict == "phishing":
        actions.append("Quarantine the message and block related indicators")
    confidence = _compute_confidence(
        score=score,
        verdict=verdict,
        judge_confidence=0.0,
        missing_count=0,
    )
    labels = derive_email_labels(
        verdict=verdict,
        risk_score=score,
        subject=email.subject,
        text=email.text,
        urls=list(precheck.get("combined_urls", [])),
    )

    return TriageResult(
        verdict=verdict,
        reason=reason,
        path=_route_path(route),
        risk_score=score,
        confidence=confidence,
        email_label=str(labels.get("email_label", "benign")),
        is_spam=bool(labels.get("is_spam", False)),
        is_phish_email=bool(labels.get("is_phish_email", False)),
        spam_score=int(labels.get("spam_score", 0)),
        threat_tags=list(labels.get("threat_tags", [])),
        indicators=list(precheck.get("indicators", [])),
        recommended_actions=list(dict.fromkeys(actions)),
        input=email.text,
        urls=list(precheck.get("combined_urls", [])),
        attachments=email.attachments,
        provider_used=f"{provider}:fallback",
        evidence={
            "evidence_pack": evidence_pack.model_dump(mode="json"),
            "precheck": precheck,
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
    fetch_timeout_s: float = 8.0
    fetch_connect_timeout_s: float = 3.0
    fetch_max_redirects: int = 3
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
    precheck_domain_suspicious_threshold: int = 35
    precheck_text_keyword_weight: int = 9
    precheck_text_urgency_weight: int = 8
    precheck_text_action_weight: int = 8
    precheck_text_core_bonus: int = 15
    precheck_text_finance_combo_bonus: int = 12
    precheck_text_suspicious_finance_bonus: int = 12
    precheck_text_suspicious_urgency_bonus: int = 8
    precheck_url_suspicious_weight: int = 24
    precheck_url_path_token_bonus: int = 8
    precheck_url_path_bonus_cap: int = 24
    precheck_url_domain_context_divisor: int = 2
    precheck_url_domain_context_cap: int = 20
    precheck_domain_token_cap: int = 30
    precheck_domain_synthetic_bonus: int = 18
    pipeline_policy: PipelinePolicy = field(default_factory=PipelinePolicy)
    _executor: PipelineExecutor | None = field(default=None, init=False, repr=False)

    def can_call_remote(self) -> bool:
        if importlib.util.find_spec("agents") is None:
            return False
        if self.provider == "openai":
            return bool(self.api_key or os.getenv("OPENAI_API_KEY"))
        return True

    def build_common_kwargs(self) -> dict[str, object]:
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

    def event(self, stage: str, status: str, message: str, data: dict[str, Any] | None = None) -> TraceEvent:
        return make_event(stage=stage, status=status, message=message, data=data)

    def _get_executor(self) -> PipelineExecutor:
        if self._executor is None:
            self.pipeline_policy = self.pipeline_policy.normalized()
            self._executor = PipelineExecutor(
                parse_input=parse_input_payload,
                evidence_builder=EvidenceBuilder(_build_evidence_pack),
                skill_router=SkillRouter(),
                judge=JudgeEngine(),
                fallback_builder=_fallback_result,
            )
        return self._executor

    def analyze_stream(self, text: str) -> Generator[TraceEvent, None, None]:
        yield from self._get_executor().analyze_stream(service=self, text=text)

    def analyze(self, text: str) -> dict[str, object]:
        return self._get_executor().analyze(service=self, text=text)
