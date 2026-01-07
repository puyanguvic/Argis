"""Risk fusion and decision policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable

from agent.state import AgentState
from agent.config import LLMConfig
from schemas.email_schema import EmailSchema
from tools.llm_client import analyze_decision


@dataclass
class PolicyConfig:
    threshold: float = 0.7
    weights: Dict[str, float] = field(
        default_factory=lambda: {
            "headers": 0.25,
            "urls": 0.35,
            "content": 0.30,
            "attachments": 0.10,
        }
    )


class PolicyEngine:
    """Combines tool scores into a single risk estimate."""

    _CRITICAL_URL_FINDINGS = {"brand_lookalike", "obfuscated_url", "ip_address_url", "punycode_domain"}

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def evaluate(
        self,
        email: EmailSchema,
        evidence: Dict[str, Any],
        llm_config: LLMConfig | None = None,
    ) -> AgentState:
        scores: Dict[str, float] = {}

        for key, data in evidence.items():
            scores[key] = float(data.get("score", 0.0))

        risk = self._weighted_sum(scores)
        label = "phishing" if risk >= self.config.threshold else "benign"

        if llm_config and llm_config.enabled:
            decision = analyze_decision(email.body or "", evidence, llm_config)
            evidence["final"] = decision
            risk = float(decision.get("risk", risk))
            label = str(decision.get("label", label))
        elif self._should_escalate(evidence):
            risk = max(risk, self.config.threshold)
            label = "phishing"

        return AgentState(email=email, evidence=evidence, scores=scores, risk=risk, label=label)

    def _weighted_sum(self, scores: Dict[str, float]) -> float:
        total = 0.0
        for key, weight in self.config.weights.items():
            total += scores.get(key, 0.0) * weight
        return min(max(total, 0.0), 1.0)

    def _should_escalate(self, evidence: Dict[str, Any]) -> bool:
        url_findings = set(self._coerce_findings(evidence.get("urls", {})))
        if not (url_findings & self._CRITICAL_URL_FINDINGS):
            return False

        content = evidence.get("content", {})
        content_findings = self._coerce_findings(content)
        if any(str(finding).startswith("time_pressure:") for finding in content_findings):
            return True

        llm_score = 0.0
        llm_data = content.get("llm")
        if isinstance(llm_data, dict):
            llm_score = float(llm_data.get("score", 0.0))
        return llm_score >= 0.8

    @staticmethod
    def _coerce_findings(section: Dict[str, Any]) -> Iterable[str]:
        findings = section.get("findings", [])
        if isinstance(findings, list):
            return [str(item) for item in findings]
        return []
