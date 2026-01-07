from __future__ import annotations

from schemas.evidence_schema import (
    DomainRiskItem,
    DomainRiskResult,
    EvidenceStore,
    HeaderAuthResult,
    QuickFeatures,
    SemanticResult,
    UrlChainHop,
    UrlChainItem,
    UrlChainResult,
)
from scoring.fusion import compute_risk_score, map_score_to_verdict
from scoring.rules import apply_hard_rules


def test_hard_rule_triggers() -> None:
    evidence = EvidenceStore(
        header_auth=HeaderAuthResult(
            spf="fail",
            dkim="pass",
            dmarc="pass",
            aligned=True,
            anomalies=[],
        ),
        semantic=SemanticResult(
            intent="credential_theft",
            urgency=2,
            brand_entities=["microsoft"],
            requested_actions=["click"],
            confidence=0.8,
        ),
        domain_risk=DomainRiskResult(
            items=[
                DomainRiskItem(
                    domain="micros0ft.com",
                    levenshtein_to_brand=1,
                    homoglyph_suspected=True,
                    risk_flags=["brand_similarity"],
                )
            ]
        ),
    )
    matches = apply_hard_rules(evidence)
    assert "spf_fail_lookalike_credential_intent" in matches


def test_score_maps_to_verdict() -> None:
    evidence = EvidenceStore(
        header_auth=HeaderAuthResult(
            spf="fail",
            dkim="fail",
            dmarc="fail",
            aligned=False,
            anomalies=[],
        ),
        quick_features=QuickFeatures(
            from_domain_mismatch=True,
            reply_to_mismatch=True,
            has_urls=True,
            suspicious_subject=True,
        ),
        semantic=SemanticResult(
            intent="credential_theft",
            urgency=3,
            brand_entities=["paypal"],
            requested_actions=["click"],
            confidence=0.9,
        ),
        url_chain=UrlChainResult(
            chains=[
                UrlChainItem(
                    input="https://bit.ly/login",
                    hops=[UrlChainHop(url="https://bit.ly/login")],
                    final_url="https://bit.ly/login",
                    final_domain="bit.ly",
                    has_ip=False,
                    suspicious_tld=False,
                    shortener=True,
                    contains_login_keywords=True,
                )
            ],
            errors=[],
        ),
    )
    score, _ = compute_risk_score(evidence)
    verdict = map_score_to_verdict(score)
    assert verdict == "phishing"
