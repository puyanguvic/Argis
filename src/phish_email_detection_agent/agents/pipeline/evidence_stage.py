"""Evidence-building stage implementation."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable

from phish_email_detection_agent.domain.email.models import EmailInput
from phish_email_detection_agent.domain.evidence import EvidencePack


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

        safe_fetch_policy = self.safe_fetch_policy_fn(service)
        attachment_policy = self.attachment_policy_fn(service)
        domain_policy = self.domain_policy_fn(service)

        t_start = time.perf_counter()
        html_url_meta = self.extract_urls_from_html_fn(email.body_html or "")
        combined_urls = list(
            dict.fromkeys(email.urls + self.extract_urls_fn(email.text) + self.extract_urls_fn(email.body_text))
        )
        combined_urls = list(dict.fromkeys(combined_urls + html_url_meta["urls"]))
        chain_flags = self.summarize_chain_flags_fn(email)
        if html_url_meta["hidden_links"]:
            chain_flags.append("hidden_html_links")
        timings["parse"] = int((time.perf_counter() - t_start) * 1000)

        t_header = time.perf_counter()
        header_signals = self.analyze_headers_fn(
            headers=email.headers,
            headers_raw=email.headers_raw,
            sender=email.sender,
            reply_to=email.reply_to,
        )
        timings["header_intel"] = int((time.perf_counter() - t_header) * 1000)

        t_url = time.perf_counter()
        url_signals, domain_reports = self.infer_url_signals_fn(
            combined_urls,
            service=service,
            fetch_policy=safe_fetch_policy,
            domain_policy=domain_policy,
            provenance=provenance,
        )
        timings["url_intel"] = int((time.perf_counter() - t_url) * 1000)

        t_nlp = time.perf_counter()
        nlp_cues = self.build_nlp_cues_fn(email)
        timings["nlp_cues"] = int((time.perf_counter() - t_nlp) * 1000)

        t_att = time.perf_counter()
        attachment_signals = self.build_attachment_signals_fn(email.attachments)
        timings["attachment_prescan"] = int((time.perf_counter() - t_att) * 1000)

        pre_score = self.compute_pre_score_fn(
            header_signals=header_signals,
            url_signals=url_signals,
            web_signals=[],
            attachment_signals=attachment_signals,
            nlp_cues=nlp_cues,
            review_threshold=service.pipeline_policy.pre_score_review_threshold,
            deep_threshold=service.pipeline_policy.pre_score_deep_threshold,
            url_suspicious_weight=service.precheck_url_suspicious_weight,
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
            t_web = time.perf_counter()
            web_signals, url_target_reports = self.build_web_signals_fn(
                url_signals,
                fetch_policy=safe_fetch_policy,
                provenance=provenance,
            )
            timings["web_snapshot"] = int((time.perf_counter() - t_web) * 1000)

            t_att_deep = time.perf_counter()
            attachment_bundle = self.analyze_attachments_fn(email.attachments, policy=attachment_policy)
            nested_urls = self.enrich_attachments_with_static_scan_fn(attachment_signals, attachment_bundle)
            if nested_urls:
                chain_flags.append("nested_url_in_attachment")
            timings["attachment_intel"] = int((time.perf_counter() - t_att_deep) * 1000)

            if nested_urls:
                extra_signals, extra_domain_reports = self.infer_url_signals_fn(
                    nested_urls,
                    service=service,
                    fetch_policy=safe_fetch_policy,
                    domain_policy=domain_policy,
                    provenance=provenance,
                )
                if extra_signals:
                    url_signals.extend(extra_signals)
                    domain_reports.extend(extra_domain_reports)

            pre_score = self.compute_pre_score_fn(
                header_signals=header_signals,
                url_signals=url_signals,
                web_signals=web_signals,
                attachment_signals=attachment_signals,
                nlp_cues=nlp_cues,
                review_threshold=service.pipeline_policy.pre_score_review_threshold,
                deep_threshold=service.pipeline_policy.pre_score_deep_threshold,
                url_suspicious_weight=service.precheck_url_suspicious_weight,
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

        precheck = {
            "chain_flags": list(dict.fromkeys(chain_flags)),
            "hidden_links": html_url_meta["hidden_links"],
            "combined_urls": list(dict.fromkeys([str(item.get("url", "")) for item in url_signals if item.get("url")])),
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
        }
        return evidence_pack, precheck
