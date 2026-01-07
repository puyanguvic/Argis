"""Configuration models for routing and scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, Any

from scoring.fusion import DEFAULT_WEIGHTS


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
class AgentConfig:
    """Top-level agent configuration."""

    router: RouterConfig = field(default_factory=RouterConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "AgentConfig":
        if not data:
            return cls()
        router_data = data.get("router", {})
        scoring_data = data.get("scoring", {})
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
        return cls(router=router, scoring=scoring)
