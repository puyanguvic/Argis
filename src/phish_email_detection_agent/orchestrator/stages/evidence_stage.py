"""Evidence-building stage implementation."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable

from phish_email_detection_agent.domain.email.models import EmailInput
from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.policy import FIXED_SKILL_CHAIN, SkillRegistry, fixed_skill_spec
from phish_email_detection_agent.policy.fixed_chain import (
    SKILL_ATTACHMENT_DEEP,
    SKILL_ATTACHMENT_SURFACE,
    SKILL_EMAIL_SURFACE,
    SKILL_HEADER_ANALYSIS,
    SKILL_NLP_CUES,
    SKILL_PAGE_CONTENT,
    SKILL_RISK_FUSION,
    SKILL_URL_RISK,
)


@dataclass(frozen=True)
class EvidenceStage:
    extract_urls_from_html_fn: Callable[[str], dict[str, Any]]
    extract_urls_fn: Callable[[str], list[str]]
    summarize_chain_flags_fn: Callable[[EmailInput], list[str]]
    analyze_headers_fn: Callable[..., dict[str, Any]]
    safe_fetch_policy_fn: Callable[[Any], Any]
    attachment_policy_fn: Callable[[Any], Any]
    domain_policy_fn: Callable[[Any], Any]
    infer_url_signals_fn: Callable[..., tuple[list[dict[str, Any]], list[dict[str, Any]]]]
    build_nlp_cues_fn: Callable[[EmailInput], dict[str, Any]]
    build_attachment_signals_fn: Callable[[list[str]], list[dict[str, Any]]]
    compute_pre_score_fn: Callable[..., dict[str, Any]]
    should_collect_deep_context_fn: Callable[[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], int], bool]
    build_web_signals_fn: Callable[..., tuple[list[dict[str, Any]], list[dict[str, Any]]]]
    analyze_attachments_fn: Callable[..., dict[str, Any]]
    enrich_attachments_with_static_scan_fn: Callable[[list[dict[str, Any]], dict[str, Any]], list[str]]
    clip_score_fn: Callable[[int], int]

    def build(self, email: EmailInput, service: Any) -> tuple[EvidencePack, dict[str, Any]]:
        timings: dict[str, int] = {}
        provenance: dict[str, list[str]] = {"limits_hit": [], "errors": []}
        skill_trace: list[dict[str, Any]] = []
        executed_skills: list[str] = []

        registry = SkillRegistry(allowed_names=set(FIXED_SKILL_CHAIN))
        registry.register(
            spec=fixed_skill_spec(SKILL_EMAIL_SURFACE),
            runner=lambda: self._skill_email_surface(email),
        )
        registry.register(
            spec=fixed_skill_spec(SKILL_HEADER_ANALYSIS),
            runner=lambda: self._skill_header_analysis(email),
        )
        registry.register(
            spec=fixed_skill_spec(SKILL_URL_RISK),
            runner=lambda urls: self._skill_url_risk(
                urls,
                service=service,
                fetch_policy=safe_fetch_policy,
                domain_policy=domain_policy,
                provenance=provenance,
            ),
        )
        registry.register(
            spec=fixed_skill_spec(SKILL_NLP_CUES),
            runner=lambda: self._skill_nlp_cues(email),
        )
        registry.register(
            spec=fixed_skill_spec(SKILL_ATTACHMENT_SURFACE),
            runner=lambda: self._skill_attachment_surface(email.attachments),
        )
        registry.register(
            spec=fixed_skill_spec(SKILL_PAGE_CONTENT),
            runner=lambda url_signals, fetch_policy: self._skill_page_content(
                url_signals=url_signals,
                fetch_policy=fetch_policy,
                provenance=provenance,
            ),
        )
        registry.register(
            spec=fixed_skill_spec(SKILL_ATTACHMENT_DEEP),
            runner=lambda attachment_signals, attachment_policy: self._skill_attachment_deep(
                attachments=email.attachments,
                attachment_signals=attachment_signals,
                attachment_policy=attachment_policy,
                chain_flags=chain_flags,
            ),
        )
        registry.register(
            spec=fixed_skill_spec(SKILL_RISK_FUSION),
            runner=lambda **kwargs: self._skill_risk_fusion(service=service, **kwargs),
        )

        def run_skill(name: str, *, timing_key: str | None = None, **kwargs: Any) -> Any:
            start = time.perf_counter()
            status = "done"
            try:
                return registry.run(name, **kwargs)
            except Exception:
                status = "error"
                raise
            finally:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                if timing_key is not None:
                    timings[timing_key] = elapsed_ms
                spec = registry.spec(name)
                executed_skills.append(spec.name)
                skill_trace.append(
                    {
                        "name": spec.name,
                        "version": spec.version,
                        "max_steps": spec.max_steps,
                        "status": status,
                        "elapsed_ms": elapsed_ms,
                    }
                )

        safe_fetch_policy = self.safe_fetch_policy_fn(service)
        attachment_policy = self.attachment_policy_fn(service)
        domain_policy = self.domain_policy_fn(service)

        html_url_meta, combined_urls, chain_flags = run_skill(
            SKILL_EMAIL_SURFACE,
            timing_key="parse",
        )
        header_signals = run_skill(
            SKILL_HEADER_ANALYSIS,
            timing_key="header_intel",
        )
        url_signals: list[dict[str, Any]] = []
        domain_reports: list[dict[str, Any]] = []
        url_signals, domain_reports = run_skill(
            SKILL_URL_RISK,
            timing_key="url_intel",
            urls=combined_urls,
        )
        nlp_cues = run_skill(
            SKILL_NLP_CUES,
            timing_key="nlp_cues",
        )
        attachment_signals = run_skill(
            SKILL_ATTACHMENT_SURFACE,
            timing_key="attachment_prescan",
        )
        pre_score = run_skill(
            SKILL_RISK_FUSION,
            header_signals=header_signals,
            url_signals=url_signals,
            web_signals=[],
            attachment_signals=attachment_signals,
            nlp_cues=nlp_cues,
        )

        deep_trigger = self.should_collect_deep_context_fn(
            pre_score,
            url_signals,
            attachment_signals,
            service.pipeline_policy.context_trigger_score,
        )

        web_signals: list[dict[str, Any]] = []
        url_target_reports: list[dict[str, Any]] = []
        attachment_bundle: dict[str, Any] = {
            "reports": [],
            "risky": [],
            "risky_count": 0,
            "extracted_urls": [],
        }

        if deep_trigger:
            web_signals, url_target_reports = run_skill(
                SKILL_PAGE_CONTENT,
                timing_key="web_snapshot",
                url_signals=url_signals,
                fetch_policy=safe_fetch_policy,
            )
            attachment_bundle, nested_urls = run_skill(
                SKILL_ATTACHMENT_DEEP,
                timing_key="attachment_intel",
                attachment_signals=attachment_signals,
                attachment_policy=attachment_policy,
            )

            if nested_urls:
                extra_signals, extra_domain_reports = run_skill(
                    SKILL_URL_RISK,
                    urls=nested_urls,
                )
                if extra_signals:
                    url_signals.extend(extra_signals)
                    domain_reports.extend(extra_domain_reports)

            pre_score = run_skill(
                SKILL_RISK_FUSION,
                header_signals=header_signals,
                url_signals=url_signals,
                web_signals=web_signals,
                attachment_signals=attachment_signals,
                nlp_cues=nlp_cues,
            )

        email_meta = {
            "message_id": email.message_id,
            "date": email.date,
            "sender": email.sender,
            "to": email.to,
            "cc": email.cc,
            "subject": email.subject,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "urls_count": len(url_signals),
            "attachments_count": len(attachment_signals),
        }

        evidence_pack = EvidencePack.model_validate(
            {
                "email_meta": email_meta,
                "header_signals": header_signals,
                "url_signals": url_signals,
                "web_signals": web_signals,
                "attachment_signals": attachment_signals,
                "nlp_cues": nlp_cues,
                "pre_score": pre_score,
                "provenance": {
                    "timing_ms": timings,
                    "limits_hit": list(dict.fromkeys(provenance["limits_hit"])),
                    "errors": list(dict.fromkeys(provenance["errors"])),
                },
            }
        )

        suspicious_urls = [
            str(item.get("url", ""))
            for item in url_signals
            if isinstance(item, dict) and item.get("risk_flags")
        ]
        risky_attachments = [
            str(item.get("filename", ""))
            for item in attachment_signals
            if isinstance(item, dict) and item.get("risk_flags")
        ]
        indicators = list(dict.fromkeys(pre_score.get("reasons", []) + chain_flags))

        text_score = int(
            (
                float(nlp_cues.get("urgency", 0.0))
                + float(nlp_cues.get("threat_language", 0.0))
                + float(nlp_cues.get("payment_or_giftcard", 0.0))
                + float(nlp_cues.get("credential_request", 0.0))
            )
            / 4
            * 100
        )
        url_score = max(
            [
                self.clip_score_fn(len(item.get("risk_flags", [])) * 14)
                for item in url_signals
                if isinstance(item, dict)
            ],
            default=0,
        )
        domain_score = max(
            [int(item.get("risk_score", 0)) for item in domain_reports if isinstance(item, dict)],
            default=0,
        )
        attachment_score = max(
            [
                self.clip_score_fn(len(item.get("risk_flags", [])) * 15)
                for item in attachment_signals
                if isinstance(item, dict)
            ],
            default=0,
        )
        ocr_score = max(
            [
                int(item.get("details", {}).get("risk_score", 0))
                for item in attachment_bundle.get("reports", [])
                if isinstance(item, dict) and item.get("type") == "image"
            ],
            default=0,
        )

        nested_urls_from_query: list[str] = []
        for signal in url_signals:
            nested = signal.get("nested_urls", [])
            if isinstance(nested, list):
                nested_urls_from_query.extend(
                    str(item).strip() for item in nested if isinstance(item, str) and str(item).strip()
                )
        nested_urls_from_query = list(dict.fromkeys(nested_urls_from_query))
        if len(nested_urls_from_query) > 20:
            provenance["limits_hit"].append("query_nested_url_cap_hit")
            nested_urls_from_query = nested_urls_from_query[:20]

        combined_urls = [
            str(item.get("url", ""))
            for item in url_signals
            if isinstance(item, dict) and str(item.get("url", "")).strip()
        ]
        combined_urls = list(dict.fromkeys(combined_urls + nested_urls_from_query))

        precheck = {
            "chain_flags": list(dict.fromkeys(chain_flags)),
            "hidden_links": html_url_meta["hidden_links"],
            "combined_urls": combined_urls,
            "nested_urls_from_query": nested_urls_from_query,
            "url_checks": [
                {"url": str(item.get("url", "")), "suspicious": bool(item.get("risk_flags"))}
                for item in url_signals
                if isinstance(item, dict)
            ],
            "url_target_reports": url_target_reports,
            "domain_reports": domain_reports,
            "attachment_checks": [
                {
                    "name": str(item.get("filename", "")),
                    "risk_score": self.clip_score_fn(len(item.get("risk_flags", [])) * 16),
                    "type": str(item.get("mime", "")),
                }
                for item in attachment_signals
                if isinstance(item, dict)
            ],
            "attachment_reports": attachment_bundle.get("reports", []),
            "attachment_extracted_urls": attachment_bundle.get("extracted_urls", []),
            "keyword_hits": [],
            "suspicious_urls": list(dict.fromkeys([item for item in suspicious_urls if item])),
            "risky_attachments": list(dict.fromkeys([item for item in risky_attachments if item])),
            "indicators": indicators,
            "component_scores": {
                "text": text_score,
                "url": url_score,
                "domain": self.clip_score_fn(domain_score),
                "attachment": attachment_score,
                "ocr": self.clip_score_fn(ocr_score),
            },
            "heuristic_score": int(evidence_pack.pre_score.risk_score),
            "fusion": {
                "risk_score": int(evidence_pack.pre_score.risk_score),
                "risk_level": (
                    "high"
                    if int(evidence_pack.pre_score.risk_score) >= 70
                    else "medium"
                    if int(evidence_pack.pre_score.risk_score) >= 35
                    else "low"
                ),
                "verdict": "phishing" if int(evidence_pack.pre_score.risk_score) >= 35 else "benign",
            },
            "fetch_policy": {
                "enabled": safe_fetch_policy.enabled,
                "backend": safe_fetch_policy.sandbox_backend,
                "allow_private_network": safe_fetch_policy.allow_private_network,
                "max_bytes": safe_fetch_policy.max_bytes,
                "max_redirects": safe_fetch_policy.max_redirects,
            },
            "skill_whitelist": list(FIXED_SKILL_CHAIN),
            "skill_chain": executed_skills,
            "skill_trace": skill_trace,
        }
        return evidence_pack, precheck

    def _skill_email_surface(self, email: EmailInput) -> tuple[dict[str, Any], list[str], list[str]]:
        html_url_meta = self.extract_urls_from_html_fn(email.body_html or "")
        combined_urls = list(
            dict.fromkeys(email.urls + self.extract_urls_fn(email.text) + self.extract_urls_fn(email.body_text))
        )
        combined_urls = list(dict.fromkeys(combined_urls + html_url_meta["urls"]))
        chain_flags = self.summarize_chain_flags_fn(email)
        if html_url_meta["hidden_links"]:
            chain_flags.append("hidden_html_links")
        return html_url_meta, combined_urls, chain_flags

    def _skill_header_analysis(self, email: EmailInput) -> dict[str, Any]:
        return self.analyze_headers_fn(
            headers=email.headers,
            headers_raw=email.headers_raw,
            sender=email.sender,
            reply_to=email.reply_to,
        )

    def _skill_url_risk(
        self,
        urls: list[str],
        *,
        service: Any,
        fetch_policy: Any,
        domain_policy: Any,
        provenance: dict[str, list[str]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return self.infer_url_signals_fn(
            urls,
            service=service,
            fetch_policy=fetch_policy,
            domain_policy=domain_policy,
            provenance=provenance,
        )

    def _skill_nlp_cues(self, email: EmailInput) -> dict[str, Any]:
        return self.build_nlp_cues_fn(email)

    def _skill_attachment_surface(self, attachments: list[str]) -> list[dict[str, Any]]:
        return self.build_attachment_signals_fn(attachments)

    def _skill_page_content(
        self,
        *,
        url_signals: list[dict[str, Any]],
        fetch_policy: Any,
        provenance: dict[str, list[str]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return self.build_web_signals_fn(
            url_signals,
            fetch_policy=fetch_policy,
            provenance=provenance,
        )

    def _skill_attachment_deep(
        self,
        *,
        attachments: list[str],
        attachment_signals: list[dict[str, Any]],
        attachment_policy: Any,
        chain_flags: list[str],
    ) -> tuple[dict[str, Any], list[str]]:
        attachment_bundle = self.analyze_attachments_fn(attachments, policy=attachment_policy)
        nested_urls = self.enrich_attachments_with_static_scan_fn(attachment_signals, attachment_bundle)
        if nested_urls:
            chain_flags.append("nested_url_in_attachment")
        return attachment_bundle, nested_urls

    def _skill_risk_fusion(
        self,
        *,
        service: Any,
        header_signals: dict[str, Any],
        url_signals: list[dict[str, Any]],
        web_signals: list[dict[str, Any]],
        attachment_signals: list[dict[str, Any]],
        nlp_cues: dict[str, Any],
    ) -> dict[str, Any]:
        return self.compute_pre_score_fn(
            header_signals=header_signals,
            url_signals=url_signals,
            web_signals=web_signals,
            attachment_signals=attachment_signals,
            nlp_cues=nlp_cues,
            review_threshold=service.pipeline_policy.pre_score_review_threshold,
            deep_threshold=service.pipeline_policy.pre_score_deep_threshold,
            url_suspicious_weight=service.precheck_url_suspicious_weight,
        )
