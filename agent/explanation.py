"""Generate structured explanations from evidence."""

from __future__ import annotations

from typing import List

from schemas.evidence_schema import EvidenceStore
from schemas.explanation_schema import Explanation


def _recommended_action(verdict: str) -> str:
    if verdict == "benign":
        return "allow"
    if verdict == "suspicious":
        return "warn"
    return "quarantine"


def _top_signals(
    hard_rules: list[str],
    breakdown: list[dict[str, float]],
    limit: int = 5,
) -> List[str]:
    if hard_rules:
        return [f"hard_rule:{code}" for code in hard_rules][:limit]
    ranked = sorted(breakdown, key=lambda item: item.get("contribution", 0.0), reverse=True)
    signals: list[str] = []
    for item in ranked:
        if item.get("contribution", 0.0) <= 0:
            continue
        signals.append(f"score_factor:{item.get('factor')}")
        if len(signals) >= limit:
            break
    return signals


def build_explanation(
    evidence: EvidenceStore,
    verdict: str,
    risk_score: int,
    breakdown: list[dict[str, float]],
) -> Explanation:
    """Create a structured explanation without chain-of-thought."""

    evidence_refs = {}
    if evidence.header_auth:
        evidence_refs["header_auth"] = evidence.header_auth.model_dump()
    if evidence.url_chain:
        evidence_refs["url_finals"] = [item.final_url for item in evidence.url_chain.chains]
        evidence_refs["url_domains"] = [item.final_domain for item in evidence.url_chain.chains]
    if evidence.domain_risk:
        evidence_refs["domain_risk"] = [
            {"domain": item.domain, "flags": item.risk_flags}
            for item in evidence.domain_risk.items
        ]
    if evidence.semantic:
        evidence_refs["semantic"] = evidence.semantic.model_dump()
    if evidence.attachment_scan:
        evidence_refs["attachments"] = [item.model_dump() for item in evidence.attachment_scan.items]

    top_signals = _top_signals(evidence.hard_rule_matches, breakdown)

    return Explanation(
        verdict=verdict,
        risk_score=risk_score,
        top_signals=top_signals,
        recommended_action=_recommended_action(verdict),
        evidence=evidence_refs,
        score_breakdown=breakdown,
    )
