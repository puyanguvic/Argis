"""Hard rules for high-confidence phishing verdicts."""

from __future__ import annotations

from schemas.evidence_schema import EvidenceStore


def _has_login_url(evidence: EvidenceStore) -> bool:
    chain = evidence.url_chain
    if not chain:
        return False
    return any(item.contains_login_keywords for item in chain.chains)


def _lookalike_domain(evidence: EvidenceStore) -> bool:
    risk = evidence.domain_risk
    if not risk:
        return False
    for item in risk.items:
        if item.homoglyph_suspected or "brand_similarity" in item.risk_flags:
            return True
    return False


def _has_executable_attachment(evidence: EvidenceStore) -> bool:
    scan = evidence.attachment_scan
    if not scan:
        return False
    return any(item.is_executable for item in scan.items)


def apply_hard_rules(evidence: EvidenceStore) -> list[str]:
    """Return hard-rule match codes that force a phishing verdict."""

    matches: list[str] = []
    header = evidence.header_auth
    semantic = evidence.semantic
    quick = evidence.quick_features

    if header and semantic and _lookalike_domain(evidence):
        if header.spf == "fail" and semantic.intent == "credential_theft":
            matches.append("spf_fail_lookalike_credential_intent")

    if header and quick and header.dmarc == "fail" and quick.reply_to_mismatch and _has_login_url(evidence):
        matches.append("dmarc_fail_reply_to_login_url")

    if semantic and semantic.intent == "malware_delivery" and _has_executable_attachment(evidence):
        matches.append("malware_intent_executable_attachment")

    return matches
