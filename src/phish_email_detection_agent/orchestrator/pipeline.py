"""Evidence-pack phishing pipeline built on OpenAI Agents SDK."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
import importlib.util
import mimetypes
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

from phish_email_detection_agent.agents.contracts import (
    EmailInput,
    EvidencePack,
    TriageResult,
)
from phish_email_detection_agent.agents.pipeline.evidence_builder import EvidenceBuilder
from phish_email_detection_agent.agents.pipeline.evidence_stage import EvidenceStage
from phish_email_detection_agent.agents.pipeline.executor import PipelineExecutor
from phish_email_detection_agent.agents.pipeline.judge import JudgeEngine
from phish_email_detection_agent.agents.pipeline.policy import PipelinePolicy
from phish_email_detection_agent.agents.pipeline.planner import Planner
from phish_email_detection_agent.agents.pipeline.router import (
    compute_confidence as _router_compute_confidence,
    map_route_to_path as _router_map_route_to_path,
    merge_judge_verdict as _router_merge_judge_verdict,
    normalize_score_for_verdict as _router_normalize_score_for_verdict,
    verdict_from_score as _router_verdict_from_score,
)
from phish_email_detection_agent.orchestrator.tracing import TraceEvent, make_event
from phish_email_detection_agent.providers.llm_openai import ProviderConfig, build_model_reference
from phish_email_detection_agent.tools.attachment.analyze import (
    AttachmentPolicy,
    analyze_attachments,
)
from phish_email_detection_agent.tools.intel.domain_intel import DomainIntelPolicy, analyze_domain
from phish_email_detection_agent.tools.intel.header_intel import analyze_headers
from phish_email_detection_agent.domain.attachment.detect import classify_attachment
from phish_email_detection_agent.domain.email.parse import (
    extract_urls_from_html,
    parse_input_payload,
    summarize_chain_flags,
)
from phish_email_detection_agent.domain.url.extract import canonicalize_url, extract_urls, is_suspicious_url
from phish_email_detection_agent.tools.registry import ToolRegistry
from phish_email_detection_agent.tools.text.text_model import (
    contains_phishing_keywords,
    derive_email_labels,
)
from phish_email_detection_agent.tools.url_fetch.service import (
    SafeFetchPolicy,
    analyze_url_target,
    safe_fetch_url,
)

_SHORTLINK_DOMAINS = ("bit.ly", "tinyurl.com", "t.co", "rb.gy")
_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".jar",
    ".ps1",
    ".hta",
    ".iso",
}
_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
_BRAND_HINTS = ("microsoft", "paypal", "apple", "google", "amazon", "bank", "dhl")
_URL_PATH_RISK_TOKENS = (
    "/verify",
    "/login",
    "/account",
    "/secure",
    "/payment",
    "/billing",
    "/portal",
    "confirm",
)

_URGENCY_PATTERNS = (
    re.compile(r"\baction required\b"),
    re.compile(r"\bwithin (?:the )?next \d+\s*(?:hours?|days?)\b"),
    re.compile(r"\bimmediately\b"),
    re.compile(r"\basap\b"),
    re.compile(r"\bfinal notice\b"),
    re.compile(r"\btemporary hold\b"),
    re.compile(r"\bservice interruption\b"),
)
_THREAT_PATTERNS = (
    re.compile(r"\baccount (?:locked|suspended|disabled)\b"),
    re.compile(r"\baccount (?:termination|terminated|closure|closed)\b"),
    re.compile(r"\baccount (?:has been )?[li]imited\b"),
    re.compile(r"\bemail account (?:has been )?limited\b"),
    re.compile(r"\b[li]imited access\b"),
    re.compile(r"\b(?:will be )?(?:shut ?down|disabled|terminated)\b"),
    re.compile(r"\bsecurity alert\b"),
    re.compile(r"\bunauthorized\b"),
    re.compile(r"\bcompromised\b"),
    re.compile(r"\bviolation detected\b"),
)
_PAYMENT_PATTERNS = (
    re.compile(r"\bpayment\b"),
    re.compile(r"\bgift\s?card\b"),
    re.compile(r"\binvoice\b"),
    re.compile(r"\bwire transfer\b"),
)
_CREDENTIAL_PATTERNS = (
    re.compile(r"\blog(?:-| )?in\b"),
    re.compile(r"\bpassword\b"),
    re.compile(r"\bverify (?:your )?(?:account|identity|credentials)\b"),
    re.compile(r"\b(?:account|email|mailbox) verification\b"),
    re.compile(r"\b(?:confirm|comfirm) (?:your )?(?:account|identity|information|credentials)\b"),
    re.compile(r"\b(?:activate|reactivate|upgrade) (?:your )?(?:account|mailbox)\b"),
    re.compile(r"\bmfa\b"),
)
_ACTION_PATTERNS = (
    re.compile(r"\bclick\b"),
    re.compile(r"\bvisit\b"),
    re.compile(r"\bopen\b"),
    re.compile(r"\b(?:confirm|comfirm|verify|activate|reactivate|upgrade)\b"),
    re.compile(r"\bplease contact (?:your )?(?:helpdesk|it support)\b"),
)
_ACCOUNT_TAKEOVER_PATTERNS = (
    re.compile(r"\baccount (?:has been )?(?:limited|locked|suspended|disabled|terminated)\b"),
    re.compile(r"\b(?:verify|confirm|comfirm|update|activate|reactivate|upgrade) (?:your )?(?:account|email|mailbox|identity|information|credentials)\b"),
    re.compile(r"\b(?:account|email|mailbox) (?:verification|activation|upgrade)\b"),
    re.compile(r"\b(?:email )?account (?:will be )?(?:shut ?down|closed|terminated|limited)\b"),
)
_PHISHING_TEXT_HINTS = (
    "verify your account",
    "account verification",
    "confirm your account",
    "comfirm your account",
    "account information",
    "account has been limited",
    "action required",
    "suspicious activity",
    "limited access",
    "iimited access",
    "account termination",
    "termination notice",
    "security alert",
    "violation detected",
    "email account has been limited",
    "pending message",
    "important upgrade",
    "activate your account",
    "account activation",
    "helpdesk",
    "docusign account",
)
_SUBJECT_ACTION_HINTS = (
    "verify",
    "verification",
    "confirm",
    "comfirm",
    "activate",
    "activation",
    "upgrade",
    "limited",
    "iimited",
    "suspend",
    "termination",
    "shut down",
    "security",
    "violation",
)
_SUBJECT_ACCOUNT_HINTS = ("account", "email", "mailbox")
_SUBJECT_BRAND_HINTS = ("microsoft", "paypal", "docusign", "usaa", "bank", "dhl", "helpdesk")
_IMPERSONATION_HINTS = (
    ("it support", "IT support"),
    ("helpdesk", "IT support"),
    ("hr", "HR"),
    ("bank", "Bank"),
    ("finance", "Finance"),
    ("microsoft", "Microsoft"),
    ("paypal", "PayPal"),
)


def _count_pattern_hits(text: str, patterns: tuple[re.Pattern[str], ...]) -> int:
    return sum(1 for pattern in patterns if pattern.search(text))


def _count_keyword_hits(text: str, hints: tuple[str, ...]) -> int:
    return sum(1 for hint in hints if hint in text)


def _clip_score(value: int) -> int:
    return max(0, min(100, int(value)))


def _risk_to_confidence(risk: int, bonus: float = 0.0) -> float:
    return max(0.0, min(1.0, round(0.35 + (risk / 100.0) * 0.55 + bonus, 2)))


def _legacy_path(route: str) -> str:
    return _router_map_route_to_path(route)


def _verdict_from_score(score: int, *, suspicious_min_score: int, suspicious_max_score: int) -> str:
    return _router_verdict_from_score(
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
    return _router_normalize_score_for_verdict(
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
    return _router_merge_judge_verdict(
        deterministic_score=deterministic_score,
        judge_verdict=judge_verdict,
        judge_confidence=judge_confidence,
        suspicious_min_score=suspicious_min_score,
        suspicious_max_score=suspicious_max_score,
    )


def _compute_confidence(*, score: int, verdict: str, judge_confidence: float, missing_count: int) -> float:
    return _router_compute_confidence(
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


def _is_shortlink(host: str) -> bool:
    return any(host == item or host.endswith(f".{item}") for item in _SHORTLINK_DOMAINS)


def _url_has_login_keywords(url: str) -> bool:
    parsed = urlparse(url or "")
    lowered = f"{parsed.path}?{parsed.query}".lower()
    return any(token in lowered for token in _URL_PATH_RISK_TOKENS)


def _infer_url_signals(
    urls: list[str],
    service: "AgentService",
    fetch_policy: SafeFetchPolicy,
    domain_policy: DomainIntelPolicy,
    provenance: dict[str, list[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    signals: list[dict[str, Any]] = []
    domain_reports: list[dict[str, Any]] = []

    for raw in urls:
        normalized = canonicalize_url(raw)
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        domain_report = analyze_domain(normalized, policy=domain_policy)
        domain_reports.append(domain_report)
        risk_flags: list[str] = []

        shortlink = _is_shortlink(host)
        if shortlink:
            risk_flags.append("shortlink")
        if "brand_typosquat" in domain_report.get("indicators", []):
            risk_flags.append("brand-spoof")
        if _url_has_login_keywords(normalized):
            risk_flags.append("login-intent")
        if "xn--" in host:
            risk_flags.append("punycode")
        if is_suspicious_url(normalized):
            risk_flags.append("suspicious-pattern")

        expanded_url = normalized
        redirect_chain: list[str] = []
        if shortlink and service.enable_url_fetch:
            expand_policy = SafeFetchPolicy(
                enabled=True,
                timeout_s=fetch_policy.timeout_s,
                connect_timeout_s=fetch_policy.connect_timeout_s,
                max_redirects=fetch_policy.max_redirects,
                max_bytes=min(65_536, fetch_policy.max_bytes),
                allow_private_network=fetch_policy.allow_private_network,
                user_agent=fetch_policy.user_agent,
                sandbox_backend=fetch_policy.sandbox_backend,
                sandbox_exec_timeout_s=fetch_policy.sandbox_exec_timeout_s,
                firejail_bin=fetch_policy.firejail_bin,
                docker_bin=fetch_policy.docker_bin,
                docker_image=fetch_policy.docker_image,
            )
            expanded = safe_fetch_url(normalized, policy=expand_policy)
            redirect_chain = [str(item) for item in expanded.get("redirect_chain", []) if isinstance(item, str)]
            candidate = str(expanded.get("final_url") or "").strip()
            if candidate:
                expanded_url = candidate
            if expanded.get("status") not in {"ok", "http_error"}:
                risk_flags.append("expansion-failed")
                provenance["errors"].append(
                    f"url_expand:{host or normalized}:{expanded.get('status', 'unknown')}"
                )
            if len(redirect_chain) >= fetch_policy.max_redirects:
                provenance["limits_hit"].append("url_expand_redirect_limit")

        final_domain = (urlparse(expanded_url).hostname or host).lower()
        typosquat = domain_report.get("typosquat_brands") if isinstance(domain_report, dict) else []
        brand = ""
        similarity = 0.0
        if isinstance(typosquat, list) and typosquat:
            brand = str(typosquat[0])
            similarity = 0.92
        else:
            for token in _BRAND_HINTS:
                if token in final_domain and not final_domain.endswith(f"{token}.com"):
                    brand = token
                    similarity = 0.74
                    if "brand-spoof" not in risk_flags:
                        risk_flags.append("brand-spoof")
                    break

        domain_risk = int(domain_report.get("risk_score", 0)) if isinstance(domain_report, dict) else 0
        signal_risk = _clip_score(
            domain_risk
            + (16 if shortlink else 0)
            + (14 if "brand-spoof" in risk_flags else 0)
            + (12 if "login-intent" in risk_flags else 0)
        )
        confidence = _risk_to_confidence(signal_risk, bonus=0.08 if shortlink else 0.0)

        signals.append(
            {
                "url": raw,
                "normalized": normalized,
                "is_shortlink": shortlink,
                "expanded_url": expanded_url,
                "redirect_chain": redirect_chain,
                "final_domain": final_domain,
                "is_punycode": "xn--" in final_domain,
                "looks_like_brand": {
                    "brand": brand,
                    "similarity": similarity,
                },
                "has_login_keywords": _url_has_login_keywords(expanded_url),
                "risk_flags": list(dict.fromkeys(risk_flags)),
                "confidence": confidence,
            }
        )
    return signals, domain_reports


def _build_nlp_cues(email: EmailInput) -> dict[str, Any]:
    raw = "\n".join([email.subject, email.text, email.body_text]).strip()
    lowered = raw.lower()
    subject_lower = str(email.subject or "").strip().lower()

    urgency_hits = _count_pattern_hits(lowered, _URGENCY_PATTERNS)
    threat_hits = _count_pattern_hits(lowered, _THREAT_PATTERNS)
    payment_hits = _count_pattern_hits(lowered, _PAYMENT_PATTERNS)
    credential_hits = _count_pattern_hits(lowered, _CREDENTIAL_PATTERNS)
    action_hits = _count_pattern_hits(lowered, _ACTION_PATTERNS)
    takeover_hits = _count_pattern_hits(lowered, _ACCOUNT_TAKEOVER_PATTERNS)
    keyword_hits = _count_keyword_hits(lowered, _PHISHING_TEXT_HINTS)
    subject_has_account = any(item in subject_lower for item in _SUBJECT_ACCOUNT_HINTS)
    subject_has_action = any(item in subject_lower for item in _SUBJECT_ACTION_HINTS)
    subject_has_brand = any(item in subject_lower for item in _SUBJECT_BRAND_HINTS)
    subject_risk_points = 0
    if subject_has_account and subject_has_action:
        subject_risk_points += 2
    if "action required" in subject_lower:
        subject_risk_points += 1
    if subject_has_brand and subject_has_action:
        subject_risk_points += 1
    if "pending" in subject_lower and "message" in subject_lower:
        subject_risk_points += 1
    if subject_lower.count("!") >= 2:
        subject_risk_points += 1

    impersonation: list[str] = []
    for needle, label in _IMPERSONATION_HINTS:
        if needle in lowered:
            impersonation.append(label)

    highlights: list[str] = []
    for block in re.split(r"(?<=[.!?])\s+|\n+", raw):
        text = block.strip()
        if not text:
            continue
        if any(token.search(text.lower()) for token in (_URGENCY_PATTERNS + _THREAT_PATTERNS + _CREDENTIAL_PATTERNS)):
            highlights.append(text[:180])
        if len(highlights) >= 4:
            break

    return {
        "urgency": min(1.0, urgency_hits / 3.0),
        "threat_language": min(1.0, threat_hits / 3.0),
        "payment_or_giftcard": min(1.0, payment_hits / 3.0),
        "credential_request": min(1.0, credential_hits / 3.0),
        "action_request": min(1.0, action_hits / 3.0),
        "account_takeover_intent": min(1.0, takeover_hits / 3.0),
        "subject_risk": min(1.0, subject_risk_points / 3.0),
        "phishing_keyword_hits": max(0, keyword_hits),
        "impersonation": list(dict.fromkeys(impersonation)),
        "highlights": highlights,
    }


def _build_attachment_signals(attachments: list[str]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for item in attachments:
        filename = str(item or "").strip()
        if not filename:
            continue
        suffix = Path(filename).suffix.lower()
        classification = classify_attachment(filename)
        guessed_mime, _ = mimetypes.guess_type(filename)
        file_size = 0
        path = Path(filename)
        if path.exists() and path.is_file():
            try:
                file_size = int(path.stat().st_size)
            except OSError:
                file_size = 0

        is_archive = suffix in _ARCHIVE_EXTENSIONS
        is_executable_like = suffix in _EXECUTABLE_EXTENSIONS
        macro_suspected = suffix in _MACRO_EXTENSIONS or classification == "macro_risk"
        risk_flags: list[str] = []
        if is_archive:
            risk_flags.append("archive")
        if is_executable_like:
            risk_flags.append("executable-like")
        if macro_suspected:
            risk_flags.append("macro-suspected")
        if classification == "high_risk":
            risk_flags.append("high-risk-extension")

        risk = 8
        risk += 28 if macro_suspected else 0
        risk += 24 if is_executable_like else 0
        risk += 10 if is_archive else 0

        signals.append(
            {
                "filename": filename,
                "mime": guessed_mime or "",
                "size": file_size,
                "extension_mismatch": False,
                "is_archive": is_archive,
                "is_executable_like": is_executable_like,
                "macro_suspected": macro_suspected,
                "risk_flags": risk_flags,
                "confidence": _risk_to_confidence(_clip_score(risk), bonus=0.03),
            }
        )
    return signals


def _extension_mismatch(filename: str, file_type: str) -> bool:
    suffix = Path(filename).suffix.lower()
    expected = {
        "pdf": {".pdf"},
        "zip": {".zip", ".docx", ".xlsx", ".pptx"},
        "ole": {".doc", ".xls", ".ppt"},
        "html": {".htm", ".html"},
        "image": {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"},
        "audio": {".wav", ".mp3", ".m4a", ".ogg", ".flac"},
    }
    if file_type not in expected:
        return False
    return bool(suffix and suffix not in expected[file_type])


def _enrich_attachments_with_static_scan(
    attachment_signals: list[dict[str, Any]],
    attachment_bundle: dict[str, Any],
) -> list[str]:
    nested_urls: list[str] = []
    reports = attachment_bundle.get("reports", [])
    report_by_name = {
        str(item.get("name", "")): item
        for item in reports
        if isinstance(item, dict) and str(item.get("name", "")).strip()
    }

    for signal in attachment_signals:
        report = report_by_name.get(signal["filename"])
        if not isinstance(report, dict):
            continue
        file_type = str(report.get("type", "")).lower()
        if _extension_mismatch(signal["filename"], file_type):
            signal["extension_mismatch"] = True
            signal["risk_flags"] = list(dict.fromkeys(signal["risk_flags"] + ["extension-mismatch"]))
        details = report.get("details", {}) if isinstance(report.get("details"), dict) else {}
        macro_like = bool(details.get("macro_like") or details.get("embedded_javascript"))
        if macro_like and not signal["macro_suspected"]:
            signal["macro_suspected"] = True
            signal["risk_flags"] = list(dict.fromkeys(signal["risk_flags"] + ["macro-suspected"]))
        extracted_urls = report.get("extracted_urls", [])
        if isinstance(extracted_urls, list):
            nested_urls.extend(str(item) for item in extracted_urls if isinstance(item, str))
            if extracted_urls:
                signal["risk_flags"] = list(dict.fromkeys(signal["risk_flags"] + ["attachment-url-chain"]))

        report_risk = _clip_score(int(report.get("risk_score", 0)))
        signal_risk = _clip_score(report_risk + (12 if signal["extension_mismatch"] else 0))
        signal["confidence"] = _risk_to_confidence(signal_risk)

    return list(dict.fromkeys(nested_urls))


def _build_web_signals(
    url_signals: list[dict[str, Any]],
    fetch_policy: SafeFetchPolicy,
    provenance: dict[str, list[str]],
    *,
    cap: int = 6,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    reports: list[dict[str, Any]] = []
    web_signals: list[dict[str, Any]] = []

    selected = url_signals[:cap]
    if len(url_signals) > cap:
        provenance["limits_hit"].append("web_snapshot_url_cap")

    for signal in selected:
        target_url = signal.get("expanded_url") or signal.get("normalized") or signal.get("url")
        report = analyze_url_target(str(target_url), policy=fetch_policy)
        reports.append(report)

        fetch = report.get("fetch", {}) if isinstance(report.get("fetch"), dict) else {}
        html = report.get("html_analysis", {}) if isinstance(report.get("html_analysis"), dict) else {}

        risk_flags: list[str] = []
        if html.get("has_password_field") and int(html.get("form_count", 0)) > 0:
            risk_flags.append("credential-harvest")
        if html.get("has_otp_field"):
            risk_flags.append("otp-collection")
        if html.get("brand_hits") and (html.get("has_password_field") or int(html.get("form_count", 0)) > 0):
            risk_flags.append("brand-impersonation")
        fetch_status = str(fetch.get("status", ""))
        if fetch_status not in {"ok", "http_error"}:
            risk_flags.append("fetch-anomaly")
            provenance["errors"].append(
                f"web_snapshot:{target_url}:{fetch_status or 'unknown'}"
            )

        web_risk = _clip_score(int(report.get("risk_score", 0)))
        web_signals.append(
            {
                "url": str(signal.get("url", target_url)),
                "fetch_ok": fetch_status == "ok",
                "http_status": int(fetch.get("status_code", 0) or 0),
                "final_url": str(fetch.get("final_url") or target_url),
                "title": str(html.get("title", ""))[:180],
                "form_count": int(html.get("form_count", html.get("login_forms", 0)) or 0),
                "has_password_field": bool(html.get("has_password_field", False)),
                "has_otp_field": bool(html.get("has_otp_field", False)),
                "external_resource_count": int(html.get("external_resource_count", 0) or 0),
                "text_brand_hints": [str(item) for item in html.get("brand_hits", []) if isinstance(item, str)],
                "risk_flags": list(dict.fromkeys(risk_flags)),
                "confidence": _risk_to_confidence(web_risk, bonus=0.04 if fetch_status == "ok" else -0.05),
            }
        )
    return web_signals, reports


def _compute_pre_score(
    *,
    header_signals: dict[str, Any],
    url_signals: list[dict[str, Any]],
    web_signals: list[dict[str, Any]],
    attachment_signals: list[dict[str, Any]],
    nlp_cues: dict[str, Any],
    review_threshold: int,
    deep_threshold: int,
    url_suspicious_weight: int,
) -> dict[str, Any]:
    reasons: list[str] = []
    score = 0

    spf_result = str(header_signals.get("spf", {}).get("result", "")).lower()
    dkim_result = str(header_signals.get("dkim", {}).get("result", "")).lower()
    dmarc_result = str(header_signals.get("dmarc", {}).get("result", "")).lower()

    if spf_result in {"fail", "softfail"}:
        score += 16
        reasons.append("header:spf_fail")
    if dkim_result == "fail":
        score += 10
        reasons.append("header:dkim_weak")
    if dmarc_result == "fail":
        score += 16
        reasons.append("header:dmarc_weak")
    if bool(header_signals.get("from_replyto_mismatch")):
        score += 12
        reasons.append("header:from_replyto_mismatch")

    received_patterns = header_signals.get("suspicious_received_patterns", [])
    if isinstance(received_patterns, list) and received_patterns:
        score += min(18, len(received_patterns) * 6)
        reasons.append("header:received_chain_anomaly")

    url_score = 0
    for signal in url_signals:
        flags = set(str(item) for item in signal.get("risk_flags", []))
        if flags:
            url_score += max(0, int(url_suspicious_weight))
        url_score += 12 if "shortlink" in flags else 0
        url_score += 16 if "brand-spoof" in flags else 0
        url_score += 14 if "login-intent" in flags else 0
        url_score += 10 if "punycode" in flags else 0
        url_score += 8 if "suspicious-pattern" in flags else 0
        if "brand-spoof" in flags:
            reasons.append("url:brand_spoof")
        if "login-intent" in flags:
            reasons.append("url:login_intent")
    score += min(60, url_score)

    web_score = 0
    for signal in web_signals:
        flags = set(str(item) for item in signal.get("risk_flags", []))
        web_score += 18 if "credential-harvest" in flags else 0
        web_score += 12 if "brand-impersonation" in flags else 0
        web_score += 8 if "otp-collection" in flags else 0
        if "credential-harvest" in flags:
            reasons.append("web:credential_harvest")
    score += min(35, web_score)

    att_score = 0
    for signal in attachment_signals:
        flags = set(str(item) for item in signal.get("risk_flags", []))
        att_score += 18 if "macro-suspected" in flags else 0
        att_score += 16 if "extension-mismatch" in flags else 0
        att_score += 14 if "executable-like" in flags else 0
        if "macro-suspected" in flags:
            reasons.append("attachment:macro_suspected")
        if "extension-mismatch" in flags:
            reasons.append("attachment:extension_mismatch")
    score += min(35, att_score)

    urgency_score = float(nlp_cues.get("urgency", 0.0))
    threat_score = float(nlp_cues.get("threat_language", 0.0))
    payment_score = float(nlp_cues.get("payment_or_giftcard", 0.0))
    credential_score = float(nlp_cues.get("credential_request", 0.0))
    action_score = float(nlp_cues.get("action_request", 0.0))
    takeover_score = float(nlp_cues.get("account_takeover_intent", 0.0))
    subject_score = float(nlp_cues.get("subject_risk", 0.0))
    keyword_hits = max(0, int(nlp_cues.get("phishing_keyword_hits", 0)))

    nlp_score = int(
        urgency_score * 14
        + threat_score * 16
        + payment_score * 9
        + credential_score * 18
        + action_score * 10
        + takeover_score * 20
        + subject_score * 18
    )
    if keyword_hits > 0:
        nlp_score += min(24, keyword_hits * 4)
        reasons.append("text:phishing_keyword_cluster")
    if credential_score > 0 and (threat_score > 0 or urgency_score > 0):
        nlp_score += 10
        reasons.append("text:credential_pressure")
    if takeover_score > 0 and (credential_score > 0 or action_score > 0):
        nlp_score += 8
        reasons.append("text:account_takeover_pattern")
    if nlp_cues.get("impersonation") and (credential_score > 0 or takeover_score > 0):
        nlp_score += 6
        reasons.append("text:impersonation_pressure")
    if subject_score > 0 and (credential_score > 0 or takeover_score > 0 or keyword_hits >= 2):
        nlp_score += 8
        reasons.append("text:subject_attack_pattern")
    if contains_phishing_keywords(" ".join(nlp_cues.get("highlights", []))):
        nlp_score += 8
        reasons.append("text:phishing_keywords")
    score += min(55, nlp_score)

    final_score = _clip_score(score)
    if final_score <= review_threshold:
        route = "allow"
    elif final_score <= deep_threshold:
        route = "review"
    else:
        route = "deep"

    return {
        "risk_score": final_score,
        "route": route,
        "reasons": list(dict.fromkeys(reasons))[:12],
    }


def _should_collect_deep_context(
    pre_score: dict[str, Any],
    url_signals: list[dict[str, Any]],
    attachment_signals: list[dict[str, Any]],
    context_trigger_score: int,
) -> bool:
    if int(pre_score.get("risk_score", 0)) >= max(0, int(context_trigger_score)):
        return True
    risky_url_flags = {"shortlink", "brand-spoof", "login-intent"}
    for signal in url_signals:
        flags = set(str(item) for item in signal.get("risk_flags", []))
        if risky_url_flags.intersection(flags):
            return True
    risky_attachment_flags = {"macro-suspected", "extension-mismatch", "executable-like"}
    for signal in attachment_signals:
        flags = set(str(item) for item in signal.get("risk_flags", []))
        if risky_attachment_flags.intersection(flags):
            return True
    return False


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
        path=_legacy_path(route),
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

    # Backward-compatible private aliases for callers that still use the previous interface.
    def _can_call_remote(self) -> bool:
        return self.can_call_remote()

    def _build_common_kwargs(self) -> dict[str, object]:
        return self.build_common_kwargs()

    def _event(self, stage: str, status: str, message: str, data: dict[str, Any] | None = None) -> TraceEvent:
        return self.event(stage=stage, status=status, message=message, data=data)

    def _get_executor(self) -> PipelineExecutor:
        if self._executor is None:
            self.pipeline_policy = self.pipeline_policy.normalized()
            self._executor = PipelineExecutor(
                parse_input=parse_input_payload,
                evidence_builder=EvidenceBuilder(_build_evidence_pack),
                planner=Planner(),
                judge=JudgeEngine(),
                fallback_builder=_fallback_result,
            )
        return self._executor

    def analyze_stream(self, text: str) -> Generator[TraceEvent, None, None]:
        yield from self._get_executor().analyze_stream(service=self, text=text)

    def analyze(self, text: str) -> dict[str, object]:
        return self._get_executor().analyze(service=self, text=text)
