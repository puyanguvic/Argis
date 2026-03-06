"""Route-aware judge context shaping."""

from __future__ import annotations

import re
from typing import Any

from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.orchestrator.evidence_store import EvidenceStore
from phish_email_detection_agent.orchestrator.verdict_routing import map_route_to_path

_PATH_BUDGETS: dict[str, dict[str, int]] = {
    "FAST": {
        "url_signals": 2,
        "attachment_signals": 1,
        "domain_reports": 2,
        "highlights": 2,
        "errors": 2,
    },
    "STANDARD": {
        "url_signals": 4,
        "attachment_signals": 2,
        "domain_reports": 3,
        "web_signals": 2,
        "highlights": 3,
        "errors": 3,
    },
    "DEEP": {
        "url_signals": 6,
        "attachment_signals": 4,
        "domain_reports": 5,
        "web_signals": 4,
        "attachment_reports": 4,
        "url_target_reports": 4,
        "highlights": 4,
        "errors": 4,
    },
}
_INDEX_TOKEN_RE = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\[(?P<index>\d+)\]$")
_LEGACY_PATH_PREFIXES = {
    "url_signals": "selected_url_signals",
    "attachment_signals": "selected_attachment_signals",
    "domain_reports": "selected_domain_reports",
    "web_signals": "selected_web_signals",
    "attachment_reports": "selected_attachment_reports",
    "url_target_reports": "selected_url_target_reports",
}


def _clean_list(values: Any, *, cap: int | None = None) -> list[str]:
    items = [str(item).strip() for item in (values or []) if isinstance(item, str) and str(item).strip()]
    deduped = list(dict.fromkeys(items))
    if cap is None:
        return deduped
    return deduped[: max(0, int(cap))]


def _score_signal(item: dict[str, Any]) -> tuple[int, int, float]:
    flags = item.get("risk_flags", [])
    confidence = float(item.get("confidence", 0.0) or 0.0)
    risky = 1 if flags else 0
    return risky, len(flags) if isinstance(flags, list) else 0, confidence


def _select_items(
    items: Any,
    *,
    cap: int,
    score_fn,
    summary_fn,
) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    prepared = [item for item in items if isinstance(item, dict)]
    prepared.sort(key=score_fn, reverse=True)
    selected = prepared[: max(0, int(cap))]
    return [summary_fn(item) for item in selected]


def _normalize_ref_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"value": value}
    return {key: val for key, val in value.items() if key not in {"evidence_id", "evidence_path"}}


def _annotate_ref(
    *,
    store: EvidenceStore,
    value: dict[str, Any],
    evidence_path: str,
    category: str,
    source: str,
    tags: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    record = store.add(
        category=category,
        payload=_normalize_ref_payload(value),
        source=source,
        tags=tags,
    )
    annotated = dict(value)
    annotated["evidence_id"] = record.evidence_id
    annotated["evidence_path"] = evidence_path
    return annotated


def _build_email_context(email_meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "message_id": str(email_meta.get("message_id", "")).strip(),
        "date": str(email_meta.get("date", "")).strip(),
        "sender": str(email_meta.get("sender", "")).strip(),
        "subject": str(email_meta.get("subject", "")).strip(),
        "reply_to": str(email_meta.get("reply_to", "")).strip(),
        "urls_count": int(email_meta.get("urls_count", 0) or 0),
        "attachments_count": int(email_meta.get("attachments_count", 0) or 0),
    }


def _build_header_summary(header_signals: dict[str, Any]) -> dict[str, Any]:
    return {
        "spf_result": str(header_signals.get("spf", {}).get("result", "")).strip().lower(),
        "dkim_result": str(header_signals.get("dkim", {}).get("result", "")).strip().lower(),
        "dmarc_result": str(header_signals.get("dmarc", {}).get("result", "")).strip().lower(),
        "from_replyto_mismatch": bool(header_signals.get("from_replyto_mismatch", False)),
        "received_hops": int(header_signals.get("received_hops", 0) or 0),
        "received_anomalies": _clean_list(header_signals.get("suspicious_received_patterns"), cap=4),
        "confidence": float(header_signals.get("confidence", 0.0) or 0.0),
    }


def _build_nlp_summary(nlp_cues: dict[str, Any], *, highlights_cap: int) -> dict[str, Any]:
    return {
        "urgency": float(nlp_cues.get("urgency", 0.0) or 0.0),
        "threat_language": float(nlp_cues.get("threat_language", 0.0) or 0.0),
        "payment_or_giftcard": float(nlp_cues.get("payment_or_giftcard", 0.0) or 0.0),
        "credential_request": float(nlp_cues.get("credential_request", 0.0) or 0.0),
        "action_request": float(nlp_cues.get("action_request", 0.0) or 0.0),
        "account_takeover_intent": float(nlp_cues.get("account_takeover_intent", 0.0) or 0.0),
        "subject_risk": float(nlp_cues.get("subject_risk", 0.0) or 0.0),
        "phishing_keyword_hits": int(nlp_cues.get("phishing_keyword_hits", 0) or 0),
        "impersonation": _clean_list(nlp_cues.get("impersonation"), cap=3),
        "highlights": _clean_list(nlp_cues.get("highlights"), cap=highlights_cap),
    }


def _summarize_url_signal(item: dict[str, Any], *, include_redirects: bool) -> dict[str, Any]:
    looks_like_brand = item.get("looks_like_brand", {})
    summary = {
        "url": str(item.get("url", "")).strip(),
        "final_domain": str(item.get("final_domain", "")).strip(),
        "is_shortlink": bool(item.get("is_shortlink", False)),
        "has_login_keywords": bool(item.get("has_login_keywords", False)),
        "domain_risk_score": int(item.get("domain_risk_score", 0) or 0),
        "risk_flags": _clean_list(item.get("risk_flags"), cap=6),
        "confidence": float(item.get("confidence", 0.0) or 0.0),
    }
    if isinstance(looks_like_brand, dict) and str(looks_like_brand.get("brand", "")).strip():
        summary["looks_like_brand"] = {
            "brand": str(looks_like_brand.get("brand", "")).strip(),
            "similarity": float(looks_like_brand.get("similarity", 0.0) or 0.0),
        }
    if include_redirects:
        summary["expanded_url"] = str(item.get("expanded_url", "")).strip()
        summary["redirect_chain"] = _clean_list(item.get("redirect_chain"), cap=4)
        summary["nested_urls"] = _clean_list(item.get("nested_urls"), cap=4)
    return summary


def _summarize_domain_report(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": str(item.get("domain", "")).strip(),
        "base_domain": str(item.get("base_domain", "")).strip(),
        "risk_score": int(item.get("risk_score", 0) or 0),
        "indicators": _clean_list(item.get("indicators"), cap=5),
        "typosquat_brands": _clean_list(item.get("typosquat_brands"), cap=3),
        "suspicious_tokens": _clean_list(item.get("suspicious_tokens"), cap=4),
    }


def _summarize_web_signal(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": str(item.get("url", "")).strip(),
        "final_url": str(item.get("final_url", "")).strip(),
        "title": str(item.get("title", "")).strip(),
        "fetch_ok": bool(item.get("fetch_ok", False)),
        "http_status": int(item.get("http_status", 0) or 0),
        "form_count": int(item.get("form_count", 0) or 0),
        "has_password_field": bool(item.get("has_password_field", False)),
        "has_otp_field": bool(item.get("has_otp_field", False)),
        "text_brand_hints": _clean_list(item.get("text_brand_hints"), cap=4),
        "risk_flags": _clean_list(item.get("risk_flags"), cap=5),
        "confidence": float(item.get("confidence", 0.0) or 0.0),
    }


def _summarize_attachment_signal(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": str(item.get("filename", "")).strip(),
        "mime": str(item.get("mime", "")).strip(),
        "extension_mismatch": bool(item.get("extension_mismatch", False)),
        "is_archive": bool(item.get("is_archive", False)),
        "is_executable_like": bool(item.get("is_executable_like", False)),
        "macro_suspected": bool(item.get("macro_suspected", False)),
        "risk_flags": _clean_list(item.get("risk_flags"), cap=6),
        "confidence": float(item.get("confidence", 0.0) or 0.0),
    }


def _attachment_detail_summary(details: Any) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    summary: dict[str, Any] = {}
    if "embedded_javascript" in details:
        summary["embedded_javascript"] = bool(details.get("embedded_javascript"))
    if "form_like_objects" in details:
        summary["form_like_objects"] = bool(details.get("form_like_objects"))
    if "macro_like" in details:
        summary["macro_like"] = bool(details.get("macro_like"))
    if "ocr_hits" in details:
        summary["ocr_hits"] = _clean_list(details.get("ocr_hits"), cap=4)
    if "brand_hits" in details:
        summary["brand_hits"] = _clean_list(details.get("brand_hits"), cap=3)
    if "transcript_hits" in details:
        summary["transcript_hits"] = _clean_list(details.get("transcript_hits"), cap=4)
    if "qr_payloads" in details:
        summary["qr_payloads_count"] = len(_clean_list(details.get("qr_payloads"), cap=6))
    if "urls" in details:
        summary["urls_count"] = len(_clean_list(details.get("urls"), cap=8))
    if "risk_score" in details:
        summary["detail_risk_score"] = int(details.get("risk_score", 0) or 0)
    for error_key in ("ocr_error", "qr_error", "transcription_error"):
        if str(details.get(error_key, "")).strip():
            summary[error_key] = str(details.get(error_key, "")).strip()
    return summary


def _summarize_attachment_report(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(item.get("name", "")).strip(),
        "type": str(item.get("type", "")).strip(),
        "risk_score": int(item.get("risk_score", 0) or 0),
        "indicators": _clean_list(item.get("indicators"), cap=6),
        "extracted_urls_count": len(_clean_list(item.get("extracted_urls"), cap=8)),
        "details": _attachment_detail_summary(item.get("details")),
    }


def _summarize_url_target_report(item: dict[str, Any]) -> dict[str, Any]:
    fetch = item.get("fetch", {}) if isinstance(item.get("fetch"), dict) else {}
    html = item.get("html_analysis", {}) if isinstance(item.get("html_analysis"), dict) else {}
    obfuscation = item.get("url_obfuscation", {}) if isinstance(item.get("url_obfuscation"), dict) else {}
    return {
        "url": str(item.get("url", "")).strip(),
        "risk_score": int(item.get("risk_score", 0) or 0),
        "fetch": {
            "status": str(fetch.get("status", "")).strip(),
            "status_code": int(fetch.get("status_code", 0) or 0),
            "final_url": str(fetch.get("final_url", "")).strip(),
            "blocked_reason": str(fetch.get("blocked_reason", "")).strip(),
        },
        "html_summary": {
            "title": str(html.get("title", "")).strip(),
            "form_count": int(html.get("form_count", 0) or 0),
            "has_password_field": bool(html.get("has_password_field", False)),
            "has_otp_field": bool(html.get("has_otp_field", False)),
            "brand_hits": _clean_list(html.get("brand_hits"), cap=4),
            "impersonation_score": int(html.get("impersonation_score", 0) or 0),
        },
        "url_obfuscation_flags": _clean_list(obfuscation.get("flags"), cap=6),
    }


def _build_precheck_summary(
    precheck: dict[str, Any],
    *,
    limits_hit: list[str],
) -> dict[str, Any]:
    context_decisions = precheck.get("context_decisions", {}) if isinstance(precheck, dict) else {}
    context_admissions = precheck.get("context_admissions", {}) if isinstance(precheck, dict) else {}
    web_context = context_decisions.get("web", {}) if isinstance(context_decisions, dict) else {}
    attachment_context = context_decisions.get("attachment", {}) if isinstance(context_decisions, dict) else {}
    summary = {
        "heuristic_score": int(precheck.get("heuristic_score", 0) or 0),
        "indicators": _clean_list(precheck.get("indicators"), cap=8),
        "chain_flags": _clean_list(precheck.get("chain_flags"), cap=6),
        "suspicious_urls": _clean_list(precheck.get("suspicious_urls"), cap=6),
        "risky_attachments": _clean_list(precheck.get("risky_attachments"), cap=4),
        "hidden_links_count": len(_clean_list(precheck.get("hidden_links"), cap=20)),
        "combined_url_count": len(_clean_list(precheck.get("combined_urls"), cap=50)),
        "component_scores": precheck.get("component_scores", {}),
        "limits_hit": limits_hit,
        "deep_context_collected": bool(web_context.get("collected", False) or attachment_context.get("collected", False)),
        "context_decisions": {
            "web": {
                "collected": bool(web_context.get("collected", False)),
                "reason": str(web_context.get("reason", "")).strip(),
                "status": str(web_context.get("status", "")).strip(),
            },
            "attachment": {
                "collected": bool(attachment_context.get("collected", False)),
                "reason": str(attachment_context.get("reason", "")).strip(),
                "status": str(attachment_context.get("status", "")).strip(),
            },
        },
        "context_admissions": context_admissions if isinstance(context_admissions, dict) else {},
    }
    if precheck.get("nested_urls_from_query"):
        summary["nested_urls_from_query"] = _clean_list(precheck.get("nested_urls_from_query"), cap=6)
    return summary


def _attach_context_refs(context: dict[str, Any]) -> dict[str, Any]:
    store = EvidenceStore()
    annotated = dict(context)
    top_level_targets = {
        "email_context": ("email", "judge_context:email"),
        "pre_score": ("pre_score", "judge_context:pre_score"),
        "precheck_summary": ("precheck", "judge_context:precheck"),
        "header_summary": ("header", "judge_context:header"),
        "nlp_summary": ("nlp", "judge_context:nlp"),
    }
    for key, (category, source) in top_level_targets.items():
        value = annotated.get(key)
        if isinstance(value, dict):
            annotated[key] = _annotate_ref(
                store=store,
                value=value,
                evidence_path=key,
                category=category,
                source=source,
                tags=[key],
            )

    list_targets = {
        "selected_url_signals": ("url_signal", "judge_context:url"),
        "selected_attachment_signals": ("attachment_signal", "judge_context:attachment_signal"),
        "selected_domain_reports": ("domain_report", "judge_context:domain"),
        "selected_web_signals": ("web_signal", "judge_context:web"),
        "selected_attachment_reports": ("attachment_report", "judge_context:attachment_report"),
        "selected_url_target_reports": ("url_target_report", "judge_context:url_target"),
    }
    for key, (category, source) in list_targets.items():
        values = annotated.get(key)
        if not isinstance(values, list):
            continue
        annotated_values: list[dict[str, Any]] = []
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                continue
            annotated_values.append(
                _annotate_ref(
                    store=store,
                    value=item,
                    evidence_path=f"{key}[{index}]",
                    category=category,
                    source=source,
                    tags=[key, annotated.get("path", "")],
                )
            )
        annotated[key] = annotated_values

    annotated["evidence_refs"] = store.refs(limit=64)
    return annotated


def resolve_evidence_id(*, judge_context: dict[str, Any], evidence_path: str) -> str:
    target = str(evidence_path or "").strip()
    if not target:
        return ""
    for legacy, current in _LEGACY_PATH_PREFIXES.items():
        if target == legacy or target.startswith(f"{legacy}[") or target.startswith(f"{legacy}."):
            target = current + target[len(legacy) :]
            break

    def _resolve_node(path: str) -> Any:
        current: Any = judge_context
        for part in path.split("."):
            clean = part.strip()
            if not clean:
                return None
            match = _INDEX_TOKEN_RE.match(clean)
            if match:
                name = match.group("name")
                index = int(match.group("index"))
                if not isinstance(current, dict):
                    return None
                current = current.get(name)
                if not isinstance(current, list) or index >= len(current):
                    return None
                current = current[index]
                continue
            if not isinstance(current, dict):
                return None
            current = current.get(clean)
        return current

    candidate = target
    while candidate:
        node = _resolve_node(candidate)
        if isinstance(node, dict):
            evidence_id = str(node.get("evidence_id", "")).strip()
            if evidence_id:
                return evidence_id
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    return ""


def build_judge_context(*, evidence_pack: EvidencePack, precheck: dict[str, Any]) -> dict[str, Any]:
    pack = evidence_pack.model_dump(mode="json")
    route = str(pack.get("pre_score", {}).get("route", "")).strip().lower()
    path = map_route_to_path(route)
    budget = _PATH_BUDGETS.get(path, _PATH_BUDGETS["STANDARD"])
    provenance = pack.get("provenance", {}) if isinstance(pack.get("provenance"), dict) else {}
    limits_hit = _clean_list(provenance.get("limits_hit"), cap=8)

    context = {
        "path": path,
        "route": route,
        "context_budget": {
            "shape": "route-aware",
            "path": path,
            "selected_url_signals": int(budget.get("url_signals", 0)),
            "selected_attachment_signals": int(budget.get("attachment_signals", 0)),
            "selected_domain_reports": int(budget.get("domain_reports", 0)),
            "selected_web_signals": int(budget.get("web_signals", 0)),
            "selected_attachment_reports": int(budget.get("attachment_reports", 0)),
        },
        "email_context": _build_email_context(pack.get("email_meta", {})),
        "pre_score": pack.get("pre_score", {}),
        "precheck_summary": _build_precheck_summary(precheck, limits_hit=limits_hit),
        "header_summary": _build_header_summary(pack.get("header_signals", {})),
        "nlp_summary": _build_nlp_summary(pack.get("nlp_cues", {}), highlights_cap=budget["highlights"]),
        "selected_url_signals": _select_items(
            pack.get("url_signals"),
            cap=budget["url_signals"],
            score_fn=_score_signal,
            summary_fn=lambda item: _summarize_url_signal(item, include_redirects=path == "DEEP"),
        ),
        "selected_attachment_signals": _select_items(
            pack.get("attachment_signals"),
            cap=budget["attachment_signals"],
            score_fn=_score_signal,
            summary_fn=_summarize_attachment_signal,
        ),
        "selected_domain_reports": _select_items(
            precheck.get("domain_reports"),
            cap=budget["domain_reports"],
            score_fn=lambda item: (int(item.get("risk_score", 0) or 0), len(item.get("indicators", []))),
            summary_fn=_summarize_domain_report,
        ),
        "provenance": {
            "limits_hit": limits_hit,
            "errors": _clean_list(provenance.get("errors"), cap=budget["errors"]),
        },
    }

    if path in {"STANDARD", "DEEP"}:
        context["selected_web_signals"] = _select_items(
            pack.get("web_signals"),
            cap=budget["web_signals"],
            score_fn=_score_signal,
            summary_fn=_summarize_web_signal,
        )

    if path == "DEEP":
        context["selected_attachment_reports"] = _select_items(
            precheck.get("attachment_reports"),
            cap=budget["attachment_reports"],
            score_fn=lambda item: (int(item.get("risk_score", 0) or 0), len(item.get("indicators", []))),
            summary_fn=_summarize_attachment_report,
        )
        context["selected_url_target_reports"] = _select_items(
            precheck.get("url_target_reports"),
            cap=budget["url_target_reports"],
            score_fn=lambda item: (
                int(item.get("risk_score", 0) or 0),
                len(item.get("html_analysis", {}).get("brand_hits", []))
                if isinstance(item.get("html_analysis"), dict)
                else 0,
            ),
            summary_fn=_summarize_url_target_report,
        )

    return _attach_context_refs(context)


__all__ = ["build_judge_context", "resolve_evidence_id"]
