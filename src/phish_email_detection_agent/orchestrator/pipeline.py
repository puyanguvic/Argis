"""Evidence-pack phishing pipeline built on OpenAI Agents SDK."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
import importlib.util
import json
import mimetypes
import os
from pathlib import Path
import re
import time
from typing import Any
from urllib.parse import urlparse

from phish_email_detection_agent.agents.contracts import (
    EmailInput,
    EvidencePack,
    JudgeOutput,
    TriageResult,
)
from phish_email_detection_agent.agents.prompts import JUDGE_PROMPT
from phish_email_detection_agent.evidence.redact import redact_value
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
from phish_email_detection_agent.tools.text.text_model import contains_phishing_keywords
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
    re.compile(r"\bsecurity alert\b"),
    re.compile(r"\bunauthorized\b"),
    re.compile(r"\bcompromised\b"),
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
    re.compile(r"\bmfa\b"),
)
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


def _clip_score(value: int) -> int:
    return max(0, min(100, int(value)))


def _risk_to_confidence(risk: int, bonus: float = 0.0) -> float:
    return max(0.0, min(1.0, round(0.35 + (risk / 100.0) * 0.55 + bonus, 2)))


def _legacy_path(route: str) -> str:
    return {
        "allow": "FAST",
        "review": "STANDARD",
        "deep": "DEEP",
    }.get(route, "STANDARD")


def _verdict_from_score(score: int, *, suspicious_min_score: int, suspicious_max_score: int) -> str:
    if score >= 35:
        return "phishing"
    if score >= suspicious_min_score and score <= suspicious_max_score:
        return "suspicious"
    return "benign"


def _normalize_score_for_verdict(
    score: int,
    verdict: str,
    *,
    suspicious_min_score: int,
    suspicious_max_score: int,
) -> int:
    clean_verdict = str(verdict or "").strip().lower()
    if clean_verdict == "phishing":
        return max(35, score)
    if clean_verdict == "suspicious":
        return max(suspicious_min_score, min(suspicious_max_score, score))
    return min(max(0, suspicious_min_score - 1), score)


def _merge_judge_verdict(
    *,
    deterministic_score: int,
    judge_verdict: str,
    judge_confidence: float,
    suspicious_min_score: int,
    suspicious_max_score: int,
) -> str:
    base = _verdict_from_score(
        deterministic_score,
        suspicious_min_score=suspicious_min_score,
        suspicious_max_score=suspicious_max_score,
    )
    clean_judge = str(judge_verdict or "").strip().lower()
    if clean_judge not in {"benign", "suspicious", "phishing"}:
        clean_judge = base

    # Keep high-score cases out of the gray zone by default.
    if deterministic_score >= 35:
        return "phishing"
    if deterministic_score < suspicious_min_score and clean_judge == "phishing":
        if judge_confidence >= 0.8:
            return "suspicious"
        return "benign"
    if deterministic_score < suspicious_min_score:
        return "benign"

    if deterministic_score > suspicious_max_score:
        return "phishing"

    if clean_judge == "suspicious":
        return "suspicious"
    if clean_judge == "phishing" and judge_confidence >= 0.65:
        return "phishing"
    if clean_judge == "benign" and judge_confidence >= 0.65:
        return "benign"
    return clean_judge


def _compute_confidence(*, score: int, verdict: str, judge_confidence: float, missing_count: int) -> float:
    confidence = float(judge_confidence) if judge_confidence > 0 else _risk_to_confidence(score)
    if missing_count > 0:
        confidence -= min(0.2, missing_count * 0.05)
    clean_verdict = str(verdict or "").strip().lower()
    if clean_verdict == "suspicious":
        confidence = min(confidence, 0.78)
    if clean_verdict == "benign" and score >= 20:
        confidence = min(confidence, 0.62)
    return max(0.0, min(1.0, round(confidence, 2)))


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

    urgency_hits = _count_pattern_hits(lowered, _URGENCY_PATTERNS)
    threat_hits = _count_pattern_hits(lowered, _THREAT_PATTERNS)
    payment_hits = _count_pattern_hits(lowered, _PAYMENT_PATTERNS)
    credential_hits = _count_pattern_hits(lowered, _CREDENTIAL_PATTERNS)

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

    nlp_score = int(
        float(nlp_cues.get("urgency", 0.0)) * 14
        + float(nlp_cues.get("threat_language", 0.0)) * 14
        + float(nlp_cues.get("payment_or_giftcard", 0.0)) * 10
        + float(nlp_cues.get("credential_request", 0.0)) * 14
    )
    if contains_phishing_keywords(" ".join(nlp_cues.get("highlights", []))):
        nlp_score += 8
        reasons.append("text:phishing_keywords")
    score += min(30, nlp_score)

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


def _build_evidence_pack(email: EmailInput, service: "AgentService") -> tuple[EvidencePack, dict[str, Any]]:
    timings: dict[str, int] = {}
    provenance: dict[str, list[str]] = {"limits_hit": [], "errors": []}

    safe_fetch_policy = _safe_fetch_policy(service)
    attachment_policy = _attachment_policy(service)
    domain_policy = _domain_policy(service)

    t_start = time.perf_counter()
    html_url_meta = extract_urls_from_html(email.body_html or "")
    combined_urls = list(dict.fromkeys(email.urls + extract_urls(email.text) + extract_urls(email.body_text)))
    combined_urls = list(dict.fromkeys(combined_urls + html_url_meta["urls"]))
    chain_flags = summarize_chain_flags(email)
    if html_url_meta["hidden_links"]:
        chain_flags.append("hidden_html_links")
    timings["parse"] = int((time.perf_counter() - t_start) * 1000)

    t_header = time.perf_counter()
    header_signals = analyze_headers(
        headers=email.headers,
        headers_raw=email.headers_raw,
        sender=email.sender,
        reply_to=email.reply_to,
    )
    timings["header_intel"] = int((time.perf_counter() - t_header) * 1000)

    t_url = time.perf_counter()
    url_signals, domain_reports = _infer_url_signals(
        combined_urls,
        service=service,
        fetch_policy=safe_fetch_policy,
        domain_policy=domain_policy,
        provenance=provenance,
    )
    timings["url_intel"] = int((time.perf_counter() - t_url) * 1000)

    t_nlp = time.perf_counter()
    nlp_cues = _build_nlp_cues(email)
    timings["nlp_cues"] = int((time.perf_counter() - t_nlp) * 1000)

    t_att = time.perf_counter()
    attachment_signals = _build_attachment_signals(email.attachments)
    timings["attachment_prescan"] = int((time.perf_counter() - t_att) * 1000)

    pre_score = _compute_pre_score(
        header_signals=header_signals,
        url_signals=url_signals,
        web_signals=[],
        attachment_signals=attachment_signals,
        nlp_cues=nlp_cues,
        review_threshold=service.pre_score_review_threshold,
        deep_threshold=service.pre_score_deep_threshold,
        url_suspicious_weight=service.precheck_url_suspicious_weight,
    )

    deep_trigger = _should_collect_deep_context(
        pre_score,
        url_signals,
        attachment_signals,
        service.context_trigger_score,
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
        web_signals, url_target_reports = _build_web_signals(
            url_signals,
            fetch_policy=safe_fetch_policy,
            provenance=provenance,
        )
        timings["web_snapshot"] = int((time.perf_counter() - t_web) * 1000)

        t_att_deep = time.perf_counter()
        attachment_bundle = analyze_attachments(email.attachments, policy=attachment_policy)
        nested_urls = _enrich_attachments_with_static_scan(attachment_signals, attachment_bundle)
        if nested_urls:
            chain_flags.append("nested_url_in_attachment")
        timings["attachment_intel"] = int((time.perf_counter() - t_att_deep) * 1000)

        if nested_urls:
            extra_signals, extra_domain_reports = _infer_url_signals(
                nested_urls,
                service=service,
                fetch_policy=safe_fetch_policy,
                domain_policy=domain_policy,
                provenance=provenance,
            )
            if extra_signals:
                url_signals.extend(extra_signals)
                domain_reports.extend(extra_domain_reports)

        pre_score = _compute_pre_score(
            header_signals=header_signals,
            url_signals=url_signals,
            web_signals=web_signals,
            attachment_signals=attachment_signals,
            nlp_cues=nlp_cues,
            review_threshold=service.pre_score_review_threshold,
            deep_threshold=service.pre_score_deep_threshold,
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
            _clip_score(len(item.get("risk_flags", [])) * 14)
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
        [_clip_score(len(item.get("risk_flags", [])) * 15) for item in attachment_signals if isinstance(item, dict)],
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
                "risk_score": _clip_score(len(item.get("risk_flags", [])) * 16),
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
            "domain": _clip_score(domain_score),
            "attachment": attachment_score,
            "ocr": _clip_score(ocr_score),
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


def _fallback_result(
    email: EmailInput,
    provider: str,
    evidence_pack: EvidencePack,
    precheck: dict[str, Any],
    *,
    suspicious_min_score: int,
    suspicious_max_score: int,
) -> TriageResult:
    score = int(evidence_pack.pre_score.risk_score)
    verdict = _verdict_from_score(
        score,
        suspicious_min_score=suspicious_min_score,
        suspicious_max_score=suspicious_max_score,
    )
    route = str(evidence_pack.pre_score.route)

    if verdict == "phishing":
        reason = "Evidence pack indicates coordinated phishing signals."
    elif verdict == "suspicious":
        reason = "Some suspicious cues were found, but evidence remains limited."
    else:
        reason = "No strong phishing evidence detected in the current evidence pack."

    actions = [
        "Do not click unknown links",
        "Verify sender through trusted channel",
    ]
    if route in {"review", "deep"}:
        actions.append("Escalate to analyst review before user interaction")
    if verdict in {"suspicious", "phishing"}:
        actions.append("Escalate to analyst review before user interaction")
    if verdict == "phishing":
        actions.append("Quarantine the message and block related indicators")
    confidence = _compute_confidence(
        score=score,
        verdict=verdict,
        judge_confidence=0.0,
        missing_count=0,
    )

    return TriageResult(
        verdict=verdict,
        reason=reason,
        path=_legacy_path(route),
        risk_score=score,
        confidence=confidence,
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
    pre_score_review_threshold: int = 30
    pre_score_deep_threshold: int = 70
    context_trigger_score: int = 35
    suspicious_min_score: int = 30
    suspicious_max_score: int = 34

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
        return make_event(stage=stage, status=status, message=message, data=data)

    def analyze_stream(self, text: str) -> Generator[TraceEvent, None, None]:
        email = parse_input_payload(text)
        evidence_pack, precheck = _build_evidence_pack(email, self)
        fallback = _fallback_result(
            email,
            self.provider,
            evidence_pack,
            precheck,
            suspicious_min_score=self.suspicious_min_score,
            suspicious_max_score=self.suspicious_max_score,
        )

        if not email.text and not email.urls and not email.attachments:
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
            yield self._event("init", "done", "Input empty; return fallback result.")
            yield {"type": "final", "result": final}
            return

        yield self._event(
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

        yield self._event(
            "header_intel",
            "done",
            "Header analysis completed.",
            data={
                "from_replyto_mismatch": evidence_pack.header_signals.from_replyto_mismatch,
                "received_hops": evidence_pack.header_signals.received_hops,
                "confidence": evidence_pack.header_signals.confidence,
            },
        )
        yield self._event(
            "url_intel",
            "done",
            "URL analysis completed.",
            data={
                "url_count": len(evidence_pack.url_signals),
                "suspicious_url_count": len(precheck.get("suspicious_urls", [])),
            },
        )
        yield self._event(
            "pre_score",
            "done",
            "Deterministic pre-score ready.",
            data=evidence_pack.pre_score.model_dump(mode="json"),
        )

        if evidence_pack.web_signals or precheck.get("attachment_reports"):
            yield self._event(
                "deep_context",
                "done",
                "Conditional web/attachment context collected.",
                data={
                    "web_signals": len(evidence_pack.web_signals),
                    "attachment_reports": len(precheck.get("attachment_reports", [])),
                },
            )

        if not self._can_call_remote():
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
            yield self._event("runtime", "fallback", "Remote model unavailable; using deterministic fallback.")
            yield {"type": "final", "result": final}
            return

        try:
            from agents import Agent, AgentOutputSchema, Runner

            common = self._build_common_kwargs()
            judge_agent = Agent(
                name="argis-evidence-judge-agent",
                instructions=JUDGE_PROMPT,
                output_type=AgentOutputSchema(JudgeOutput, strict_json_schema=False),
                **common,
            )

            redacted_pack = redact_value(evidence_pack.model_dump(mode="json"))
            yield self._event("judge", "running", "Judge agent is evaluating the evidence pack.")
            judge_run = Runner.run_sync(
                judge_agent,
                json.dumps({"evidence_pack": redacted_pack}, ensure_ascii=True),
                max_turns=self.max_turns,
            )
            judge_output = JudgeOutput.model_validate(getattr(judge_run, "final_output", {}))
            yield self._event(
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

            deterministic_score = int(evidence_pack.pre_score.risk_score)
            judge_score = _clip_score(int(judge_output.risk_score))
            merged_score = max(deterministic_score, judge_score)
            merged_verdict = _merge_judge_verdict(
                deterministic_score=deterministic_score,
                judge_verdict=judge_output.verdict,
                judge_confidence=float(judge_output.confidence),
                suspicious_min_score=self.suspicious_min_score,
                suspicious_max_score=self.suspicious_max_score,
            )
            merged_score = _normalize_score_for_verdict(
                merged_score,
                merged_verdict,
                suspicious_min_score=self.suspicious_min_score,
                suspicious_max_score=self.suspicious_max_score,
            )
            merged_confidence = _compute_confidence(
                score=merged_score,
                verdict=merged_verdict,
                judge_confidence=float(judge_output.confidence),
                missing_count=len(judge_output.missing_info),
            )
            merged_actions = list(
                dict.fromkeys(
                    fallback.recommended_actions + list(judge_output.recommended_actions)
                )
            )
            merged_indicators = list(
                dict.fromkeys(
                    list(precheck.get("indicators", []))
                    + [item.claim for item in judge_output.top_evidence]
                )
            )

            final = TriageResult(
                verdict=merged_verdict,
                reason=judge_output.reason.strip() or fallback.reason,
                path=_legacy_path(evidence_pack.pre_score.route),
                risk_score=merged_score,
                confidence=merged_confidence,
                indicators=merged_indicators,
                recommended_actions=merged_actions,
                input=email.text,
                urls=list(precheck.get("combined_urls", [])),
                attachments=email.attachments,
                provider_used=self.provider,
                evidence={
                    "evidence_pack": evidence_pack.model_dump(mode="json"),
                    "judge": judge_output.model_dump(mode="json"),
                    "precheck": precheck,
                },
            ).model_dump(mode="json")
            final["precheck"] = precheck

            yield self._event("judge", "done", "Final verdict ready.")
            yield {"type": "final", "result": final}
        except Exception as exc:
            final = fallback.model_dump(mode="json")
            final["precheck"] = precheck
            yield self._event("runtime", "error", f"Judge failed: {type(exc).__name__}. Use fallback.")
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
        evidence_pack, precheck = _build_evidence_pack(email, self)
        return _fallback_result(
            email,
            self.provider,
            evidence_pack,
            precheck,
            suspicious_min_score=self.suspicious_min_score,
            suspicious_max_score=self.suspicious_max_score,
        ).model_dump(mode="json")
