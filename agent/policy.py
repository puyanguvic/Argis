"""Policy layer for verdict decisions."""

from __future__ import annotations

from agent.config import AgentConfig
from schemas.evidence_schema import EvidenceStore
from scoring.fusion import compute_risk_score, map_score_to_verdict
from scoring.rules import apply_hard_rules


class PolicyEngine:
    """Fuse evidence into a verdict using rules and scores."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config

    def decide(self, evidence: EvidenceStore) -> tuple[str, int, list[dict[str, float]]]:
        evidence.hard_rule_matches = apply_hard_rules(evidence)
        risk_score, breakdown = compute_risk_score(evidence, self.config.scoring.weights)
        verdict = map_score_to_verdict(risk_score)
        if evidence.hard_rule_matches:
            verdict = "phishing"
            risk_score = max(risk_score, 70)
        return verdict, risk_score, breakdown
