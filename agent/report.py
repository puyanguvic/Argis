"""Human-readable phishing detection report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from schemas.evidence_schema import EvidenceStore


@dataclass(frozen=True)
class EvidenceLine:
    section: str
    severity: str
    message: str
    evidence_id: str
    score_hint: float


def _confidence(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MED"
    return "LOW"


def _verdict_label(verdict: str) -> str:
    if verdict == "phishing":
        return "QUARANTINE"
    if verdict == "suspicious":
        return "ESCALATE"
    return "ALLOW"


def _recommended_actions(verdict: str, confidence: str) -> list[str]:
    if verdict == "phishing":
        return [
            "Quarantine this email and block external links.",
            "Notify the user with a security warning.",
            "Escalate to Security if sender is new.",
        ]
    if verdict == "suspicious":
        return [
            "Escalate for security review before approval.",
            "Warn the user and disable external links.",
        ]
    actions = ["Allow the email with normal delivery.", "No escalation required."]
    if confidence == "LOW":
        actions.append(
            "Limited evidence collected in this profile. If this request is unexpected, verify with the sender via an internal channel."
        )
    return actions


def _evidence_lines(evidence: EvidenceStore) -> list[EvidenceLine]:
    lines: list[EvidenceLine] = []
    auth = evidence.header_auth
    if auth:
        if auth.dmarc == "fail":
            lines.append(
                EvidenceLine(
                    section="Sender authentication",
                    severity="HIGH",
                    message="DMARC failed and is not aligned with From domain.",
                    evidence_id="ev-0003",
                    score_hint=12.0,
                )
            )
        if auth.spf == "fail":
            lines.append(
                EvidenceLine(
                    section="Sender authentication",
                    severity="MED",
                    message="SPF failed for the sender.",
                    evidence_id="ev-0001",
                    score_hint=8.0,
                )
            )
        if auth.dkim == "fail":
            lines.append(
                EvidenceLine(
                    section="Sender authentication",
                    severity="MED",
                    message="DKIM failed for the sender.",
                    evidence_id="ev-0002",
                    score_hint=6.0,
                )
            )

    if evidence.url_chain and evidence.url_chain.chains:
        for item in evidence.url_chain.chains:
            if item.contains_login_keywords:
                lines.append(
                    EvidenceLine(
                        section="URL / Domain",
                        severity="MED",
                        message="URL contains login or verification keywords.",
                        evidence_id="ev-0010",
                        score_hint=8.0,
                    )
                )
                break
        for item in evidence.url_chain.chains:
            if item.shortener:
                lines.append(
                    EvidenceLine(
                        section="URL / Domain",
                        severity="LOW",
                        message="URL uses a known shortener.",
                        evidence_id="ev-0011",
                        score_hint=4.0,
                    )
                )
                break
        for item in evidence.url_chain.chains:
            if item.suspicious_tld:
                lines.append(
                    EvidenceLine(
                        section="URL / Domain",
                        severity="MED",
                        message=f"Suspicious TLD detected in `{item.final_domain}`.",
                        evidence_id="ev-0013",
                        score_hint=4.0,
                    )
                )
                break

    if evidence.domain_risk:
        for item in evidence.domain_risk.items:
            if item.homoglyph_suspected or "brand_similarity" in item.risk_flags:
                lines.append(
                    EvidenceLine(
                        section="URL / Domain",
                        severity="HIGH",
                        message=f"Lookalike domain `{item.domain}` detected.",
                        evidence_id="ev-0012",
                        score_hint=10.0,
                    )
                )
                break

    if evidence.semantic:
        semantic = evidence.semantic
        if semantic.intent == "credential_theft":
            lines.append(
                EvidenceLine(
                    section="Content",
                    severity="MED",
                    message="Email content urges credential verification.",
                    evidence_id="ev-0021",
                    score_hint=10.0,
                )
            )
        if semantic.urgency_level >= 2:
            lines.append(
                EvidenceLine(
                    section="Content",
                    severity="MED",
                    message="Urgency language detected in the content.",
                    evidence_id="ev-0022",
                    score_hint=4.0,
                )
            )

    if evidence.attachment_scan:
        for item in evidence.attachment_scan.items:
            if item.has_macro:
                lines.append(
                    EvidenceLine(
                        section="Attachments",
                        severity="MED",
                        message="Macro-enabled attachment detected.",
                        evidence_id="ev-0031",
                        score_hint=3.0,
                    )
                )
                break
        for item in evidence.attachment_scan.items:
            if item.is_executable:
                lines.append(
                    EvidenceLine(
                        section="Attachments",
                        severity="HIGH",
                        message="Executable attachment detected.",
                        evidence_id="ev-0032",
                        score_hint=3.0,
                    )
                )
                break

    return lines


def _rank_lines(lines: Iterable[EvidenceLine]) -> list[EvidenceLine]:
    severity_rank = {"HIGH": 3, "MED": 2, "LOW": 1}
    return sorted(
        lines,
        key=lambda item: (severity_rank.get(item.severity, 0), item.score_hint),
        reverse=True,
    )


def build_report(result) -> str:
    """Render a phishing detection report in Markdown."""

    evidence = result.evidence
    lines = _rank_lines(_evidence_lines(evidence))
    top_reasons = lines[:3]

    verdict_label = _verdict_label(result.verdict)
    confidence = _confidence(result.risk_score)
    profile = evidence.plan.path if evidence.plan else (evidence.path or "STANDARD")

    report_lines: list[str] = []
    report_lines.append("# Phishing Detection Report")
    report_lines.append("")
    report_lines.append(
        f"**Verdict:** {verdict_label} ({confidence}, score {result.risk_score}/100)  "
    )
    report_lines.append(f"**Confidence:** {confidence}  ")
    report_lines.append(f"**Trace ID:** {result.trace_id}  ")
    report_lines.append(f"**Profile:** {profile}")
    report_lines.append("")
    report_lines.append("## Top reasons")
    if top_reasons:
        for idx, item in enumerate(top_reasons, start=1):
            report_lines.append(f"{idx}. {item.message}")
    else:
        report_lines.append(
            "1. Limited evidence collected; no material risk indicators observed in this profile."
        )
    report_lines.append("")
    report_lines.append("## Recommended actions")
    for action in _recommended_actions(result.verdict, confidence):
        report_lines.append(f"- {action}")
    report_lines.append("")
    report_lines.append("## Evidence (details)")

    sections = ["Sender authentication", "URL / Domain", "Content", "Attachments"]
    for section in sections:
        section_lines = [item for item in lines if item.section == section]
        if not section_lines:
            continue
        report_lines.append(f"### {section}")
        for item in section_lines:
            report_lines.append(
                f"- **[{item.severity}]** {item.message} ({item.evidence_id})"
            )
        report_lines.append("")

    report_lines.append("## Runtime")
    report_lines.append(f"Total: {result.runtime_ms}ms")
    return "\n".join(report_lines).strip() + "\n"
