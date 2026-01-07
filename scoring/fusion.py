"""Risk fusion scoring."""

from __future__ import annotations

from typing import Dict, List

from schemas.evidence_schema import EvidenceStore

DEFAULT_WEIGHTS: Dict[str, float] = {
    "spf_fail": 12.0,
    "dkim_fail": 6.0,
    "dmarc_fail": 12.0,
    "reply_to_mismatch": 8.0,
    "from_domain_mismatch": 6.0,
    "url_present": 4.0,
    "url_login_keywords": 8.0,
    "url_shortener": 4.0,
    "url_ip_host": 6.0,
    "url_suspicious_tld": 4.0,
    "lookalike_domain": 10.0,
    "semantic_credential_intent": 10.0,
    "semantic_urgency": 4.0,
    "collaboration_oauth_intent": 10.0,
    "attachment_macro": 3.0,
    "attachment_executable": 3.0,
}


def _any_url(chain, attr: str) -> bool:
    if not chain:
        return False
    return any(getattr(item, attr, False) for item in chain.chains)


def _any_attachment(scan, attr: str) -> bool:
    if not scan:
        return False
    return any(getattr(item, attr, False) for item in scan.items)


def _lookalike_domain(domain_risk) -> bool:
    if not domain_risk:
        return False
    for item in domain_risk.items:
        if item.homoglyph_suspected or "brand_similarity" in item.risk_flags:
            return True
    return False


def compute_risk_score(
    evidence: EvidenceStore,
    weights: Dict[str, float] | None = None,
) -> tuple[int, List[dict[str, float]]]:
    """Compute a 0-100 risk score and a per-factor breakdown."""

    weights = weights or DEFAULT_WEIGHTS
    header = evidence.header_auth
    quick = evidence.quick_features
    semantic = evidence.semantic

    oauth_intents = {
        "delegated_access",
        "permission_change",
        "access_review",
        "oauth_consent",
    }
    factors: Dict[str, float] = {
        "spf_fail": 1.0 if header and header.spf == "fail" else 0.0,
        "dkim_fail": 1.0 if header and header.dkim == "fail" else 0.0,
        "dmarc_fail": 1.0 if header and header.dmarc == "fail" else 0.0,
        "reply_to_mismatch": 1.0 if quick and quick.reply_to_mismatch else 0.0,
        "from_domain_mismatch": 1.0 if quick and quick.from_domain_mismatch else 0.0,
        "url_present": 1.0 if quick and quick.has_urls else 0.0,
        "url_login_keywords": 1.0 if _any_url(evidence.url_chain, "contains_login_keywords") else 0.0,
        "url_shortener": 1.0 if _any_url(evidence.url_chain, "shortener") else 0.0,
        "url_ip_host": 1.0 if _any_url(evidence.url_chain, "has_ip") else 0.0,
        "url_suspicious_tld": 1.0 if _any_url(evidence.url_chain, "suspicious_tld") else 0.0,
        "lookalike_domain": 1.0 if _lookalike_domain(evidence.domain_risk) else 0.0,
        "semantic_credential_intent": 1.0
        if semantic and semantic.intent == "credential_theft"
        else 0.0,
        "semantic_urgency": (semantic.urgency_level / 3.0) if semantic else 0.0,
        "collaboration_oauth_intent": 1.0
        if semantic and semantic.intent in oauth_intents
        else 0.0,
        "attachment_macro": 1.0 if _any_attachment(evidence.attachment_scan, "has_macro") else 0.0,
        "attachment_executable": 1.0
        if _any_attachment(evidence.attachment_scan, "is_executable")
        else 0.0,
    }

    breakdown: List[dict[str, float]] = []
    score = 0.0
    for key, weight in weights.items():
        value = factors.get(key, 0.0)
        contribution = weight * value
        score += contribution
        breakdown.append(
            {"factor": key, "value": value, "weight": weight, "contribution": contribution}
        )
    score = max(0.0, min(score, 100.0))
    return int(round(score)), breakdown


def map_score_to_verdict(
    score: int,
    *,
    block_threshold: int = 70,
    escalate_threshold: int = 30,
) -> str:
    """Map a score to a discrete verdict."""

    if score >= block_threshold:
        return "phishing"
    if score >= escalate_threshold:
        return "suspicious"
    return "benign"
