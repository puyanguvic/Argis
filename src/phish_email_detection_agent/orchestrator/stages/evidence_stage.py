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
    should_collect_web_context_fn: Callable[[dict[str, Any], list[dict[str, Any]], int], dict[str, Any]]
    should_collect_attachment_context_fn: Callable[[dict[str, Any], list[dict[str, Any]], int], dict[str, Any]]
    build_web_signals_fn: Callable[..., tuple[list[dict[str, Any]], list[dict[str, Any]]]]
    analyze_attachments_fn: Callable[..., dict[str, Any]]
    enrich_attachments_with_static_scan_fn: Callable[[list[dict[str, Any]], dict[str, Any]], list[str]]
    clip_score_fn: Callable[[int], int]

    def build(self, email: EmailInput, service: Any) -> tuple[EvidencePack, dict[str, Any]]:
        timings: dict[str, int] = {}
        provenance: dict[str, Any] = {"limits_hit": [], "errors": [], "context_admissions": {}}
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

        web_context_decision = self.should_collect_web_context_fn(
            pre_score,
            url_signals,
            service.pipeline_policy.context_trigger_score,
        )
        attachment_context_decision = self.should_collect_attachment_context_fn(
            pre_score,
            attachment_signals,
            service.pipeline_policy.context_trigger_score,
        )
        web_requested = bool(web_context_decision.get("collect", False))
        attachment_requested = bool(attachment_context_decision.get("collect", False))
        web_context_collect = web_requested and bool(url_signals) and bool(safe_fetch_policy.enabled)
        attachment_context_collect = attachment_requested and bool(attachment_signals)

        web_signals: list[dict[str, Any]] = []
        url_target_reports: list[dict[str, Any]] = []
        attachment_bundle: dict[str, Any] = {
            "reports": [],
            "risky": [],
            "risky_count": 0,
            "extracted_urls": [],
        }

        if web_context_collect:
            web_signals, url_target_reports = run_skill(
                SKILL_PAGE_CONTENT,
                timing_key="web_snapshot",
                url_signals=url_signals,
                fetch_policy=safe_fetch_policy,
            )
        nested_urls: list[str] = []
        if attachment_context_collect:
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

        if web_context_collect or attachment_context_collect:
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

        limits_hit = list(dict.fromkeys(provenance["limits_hit"]))

        def build_context_admission(
            *,
            name: str,
            requested: bool,
            collected: bool,
            decision_reason: str,
            candidate_count: int,
            collected_count: int,
            policy_enabled: bool | None,
            limit_prefixes: tuple[str, ...] = (),
        ) -> dict[str, Any]:
            caps_hit = [
                item
                for item in limits_hit
                if any(item.startswith(prefix) for prefix in limit_prefixes)
            ]
            if collected:
                status = "admitted"
                reason = decision_reason
            elif policy_enabled is False and requested:
                status = "skipped_by_policy"
                reason = f"{name}_policy_disabled"
            elif candidate_count <= 0:
                status = "skipped_by_signal"
                reason = f"no_{name}_candidates"
            else:
                status = "skipped_by_score"
                reason = decision_reason
            return {
                "requested": requested,
                "collected": collected,
                "status": status,
                "reason": str(reason or "").strip(),
                "candidate_count": candidate_count,
                "collected_count": collected_count,
                "capped": bool(caps_hit),
                "caps_hit": caps_hit,
            }

        context_admissions = {
            "web": build_context_admission(
                name="web",
                requested=web_requested,
                collected=web_context_collect,
                decision_reason=str(web_context_decision.get("reason", "")),
                candidate_count=len(url_signals),
                collected_count=len(web_signals),
                policy_enabled=bool(safe_fetch_policy.enabled),
                limit_prefixes=("web_snapshot_",),
            ),
            "attachment": build_context_admission(
                name="attachment",
                requested=attachment_requested,
                collected=attachment_context_collect,
                decision_reason=str(attachment_context_decision.get("reason", "")),
                candidate_count=len(attachment_signals),
                collected_count=len(attachment_bundle.get("reports", [])),
                policy_enabled=None,
            ),
        }
        provenance["context_admissions"] = context_admissions

        combined_urls = [
            str(item.get("url", ""))
            for item in url_signals
            if isinstance(item, dict) and str(item.get("url", "")).strip()
        ]
        combined_urls = list(dict.fromkeys(combined_urls + nested_urls_from_query))
        pre_score_value = int(pre_score.get("risk_score", 0))
        phishing_min_score = max(1, int(service.pipeline_policy.suspicious_max_score) + 1)

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
            "heuristic_score": pre_score_value,
            "fusion": {
                "risk_score": pre_score_value,
                "risk_level": (
                    "high"
                    if pre_score_value >= int(service.pipeline_policy.pre_score_deep_threshold)
                    else "medium"
                    if pre_score_value >= phishing_min_score
                    else "low"
                ),
                "verdict": "phishing" if pre_score_value >= phishing_min_score else "benign",
            },
            "fetch_policy": {
                "enabled": safe_fetch_policy.enabled,
                "backend": safe_fetch_policy.sandbox_backend,
                "allow_private_network": safe_fetch_policy.allow_private_network,
                "max_bytes": safe_fetch_policy.max_bytes,
                "max_redirects": safe_fetch_policy.max_redirects,
            },
            "context_decisions": {
                "web": {
                    "collected": bool(context_admissions["web"]["collected"]),
                    "reason": str(context_admissions["web"]["reason"]),
                    "status": str(context_admissions["web"]["status"]),
                    "candidate_urls": len(url_signals),
                    "collected_signals": len(web_signals),
                },
                "attachment": {
                    "collected": bool(context_admissions["attachment"]["collected"]),
                    "reason": str(context_admissions["attachment"]["reason"]),
                    "status": str(context_admissions["attachment"]["status"]),
                    "candidate_attachments": len(attachment_signals),
                    "collected_reports": len(attachment_bundle.get("reports", [])),
                },
            },
            "context_admissions": context_admissions,
            "skill_whitelist": list(FIXED_SKILL_CHAIN),
            "skill_chain": executed_skills,
            "skill_trace": skill_trace,
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
                    "limits_hit": limits_hit,
                    "errors": list(dict.fromkeys(provenance["errors"])),
                    "context_admissions": context_admissions,
                },
            }
        )
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
            domain_suspicious_threshold=service.precheck_domain_suspicious_threshold,
            url_path_token_bonus=service.precheck_url_path_token_bonus,
            url_path_bonus_cap=service.precheck_url_path_bonus_cap,
            url_domain_context_divisor=service.precheck_url_domain_context_divisor,
            url_domain_context_cap=service.precheck_url_domain_context_cap,
            text_keyword_weight=service.precheck_text_keyword_weight,
            text_urgency_weight=service.precheck_text_urgency_weight,
            text_action_weight=service.precheck_text_action_weight,
            text_core_bonus=service.precheck_text_core_bonus,
            text_finance_combo_bonus=service.precheck_text_finance_combo_bonus,
            text_suspicious_finance_bonus=service.precheck_text_suspicious_finance_bonus,
            text_suspicious_urgency_bonus=service.precheck_text_suspicious_urgency_bonus,
        )
