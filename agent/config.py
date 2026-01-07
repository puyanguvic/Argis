"""Configuration models for routing and scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, Any, List

from scoring.fusion import DEFAULT_WEIGHTS

DEFAULT_CONTEXTUAL_BRANDS = [
    "SharePoint",
    "OneDrive",
    "Google Drive",
    "DocuSign",
    "Microsoft",
    "Google",
]
DEFAULT_CONTEXTUAL_INTENTS = [
    "delegated_access",
    "permission_change",
    "access_review",
    "oauth_consent",
]
DEFAULT_CONTEXTUAL_KEYWORDS = [
    "permission scope",
    "access review",
    "confirm access",
    "sync across devices",
    "authorize",
    "consent",
]


@dataclass
class RouterConfig:
    """Thresholds for routing."""

    t_fast: float = 20.0
    t_deep: float = 60.0
    fast_tools: tuple[str, ...] = ("header_auth_check", "semantic_extract")
    standard_tools: tuple[str, ...] = (
        "header_auth_check",
        "semantic_extract",
        "url_chain_resolve",
    )
    deep_tools: tuple[str, ...] = (
        "header_auth_check",
        "semantic_extract",
        "url_chain_resolve",
        "domain_risk_assess",
        "attachment_static_scan",
    )
    budget_ms: int = 1500
    timeout_s: float = 2.0
    fallback: str = "STANDARD"


@dataclass
class ScoringConfig:
    """Scoring weights configuration."""

    weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))


@dataclass
class ThresholdConfig:
    """Verdict thresholds for policy mapping."""

    block_threshold: float = 70.0
    escalate_threshold: float = 30.0


@dataclass
class ContextualEscalationConfig:
    """Routing triggers for collaboration/OAuth patterns."""

    enabled: bool = True
    brands: List[str] = field(default_factory=lambda: list(DEFAULT_CONTEXTUAL_BRANDS))
    intents: List[str] = field(default_factory=lambda: list(DEFAULT_CONTEXTUAL_INTENTS))
    keywords: List[str] = field(default_factory=lambda: list(DEFAULT_CONTEXTUAL_KEYWORDS))


@dataclass
class AgentConfig:
    """Top-level agent configuration."""

    router: RouterConfig = field(default_factory=RouterConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    contextual_escalation: ContextualEscalationConfig = field(
        default_factory=ContextualEscalationConfig
    )
    allowlist_domains: List[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "AgentConfig":
        if not data:
            return cls()
        router_data = data.get("router", {})
        scoring_data = data.get("scoring", {})
        threshold_data = data.get("thresholds", {})
        escalation_data = data.get("contextual_escalation", {})
        allowlist_domains = data.get("allowlist_domains", [])
        router = RouterConfig(
            t_fast=float(router_data.get("t_fast", RouterConfig.t_fast)),
            t_deep=float(router_data.get("t_deep", RouterConfig.t_deep)),
            fast_tools=tuple(router_data.get("fast_tools", RouterConfig.fast_tools)),
            standard_tools=tuple(
                router_data.get("standard_tools", RouterConfig.standard_tools)
            ),
            deep_tools=tuple(router_data.get("deep_tools", RouterConfig.deep_tools)),
            budget_ms=int(router_data.get("budget_ms", RouterConfig.budget_ms)),
            timeout_s=float(router_data.get("timeout_s", RouterConfig.timeout_s)),
            fallback=str(router_data.get("fallback", RouterConfig.fallback)),
        )
        weights = dict(DEFAULT_WEIGHTS)
        custom_weights = scoring_data.get("weights")
        if isinstance(custom_weights, dict):
            for key, value in custom_weights.items():
                weights[key] = float(value)
        scoring = ScoringConfig(weights=weights)
        thresholds = ThresholdConfig(
            block_threshold=float(
                threshold_data.get("block_threshold", ThresholdConfig.block_threshold)
            ),
            escalate_threshold=float(
                threshold_data.get("escalate_threshold", ThresholdConfig.escalate_threshold)
            ),
        )
        contextual_escalation = ContextualEscalationConfig(
            enabled=bool(escalation_data.get("enabled", ContextualEscalationConfig.enabled)),
            brands=list(escalation_data.get("brands", DEFAULT_CONTEXTUAL_BRANDS)),
            intents=list(escalation_data.get("intents", DEFAULT_CONTEXTUAL_INTENTS)),
            keywords=list(escalation_data.get("keywords", DEFAULT_CONTEXTUAL_KEYWORDS)),
        )
        if not isinstance(allowlist_domains, list):
            allowlist_domains = []
        return cls(
            router=router,
            scoring=scoring,
            thresholds=thresholds,
            contextual_escalation=contextual_escalation,
            allowlist_domains=[str(item).lower() for item in allowlist_domains],
        )
