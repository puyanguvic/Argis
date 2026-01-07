"""Main agent flow coordinating tools and policy."""

from __future__ import annotations

from pathlib import Path
import yaml

from agent.config import LLMConfig
from agent.graph import build_agent_graph
from agent.policy import PolicyConfig, PolicyEngine
from agent.state import AgentState
from schemas.email_schema import EmailSchema
from tools.llm_client import analyze_decision, analyze_tao_action
from tools.parser import parse_raw_email
from tools.tool_registry import default_tool_registry, describe_tools


class AgentOrchestrator:
    """Coordinates analysis tools and applies decision policy."""

    def __init__(
        self,
        policy: PolicyEngine | None = None,
        config_path: str | Path | None = "configs/default.yaml",
    ) -> None:
        if policy is not None:
            self.policy = policy
            self.llm_config = LLMConfig()
        else:
            policy_config, llm_config = self._load_configs(config_path)
            self.policy = PolicyEngine(config=policy_config)
            self.llm_config = llm_config
        self.graph = build_agent_graph(self.policy)

    def run(self, raw_email: str) -> AgentState:
        if self.llm_config.enabled and self.llm_config.use_tao:
            return self._run_tao(raw_email)
        result = self.graph.invoke({"raw_email": raw_email, "llm_config": self.llm_config})
        return result["result"]

    def run_parsed(self, email: EmailSchema) -> AgentState:
        if self.llm_config.enabled and self.llm_config.use_tao:
            return self._run_tao_parsed(email)
        result = self.graph.invoke({"email": email, "llm_config": self.llm_config})
        return result["result"]

    def _run_tao(self, raw_email: str) -> AgentState:
        email = parse_raw_email(raw_email)
        return self._run_tao_parsed(email)

    def _run_tao_parsed(self, email: EmailSchema) -> AgentState:
        evidence: dict[str, object] = {}
        steps: list[dict[str, str]] = []

        registry = default_tool_registry()
        allowed_actions = [action for action in self.llm_config.tao_actions if action in registry]
        remaining = set(allowed_actions)
        tools = [registry[action] for action in allowed_actions]
        tool_descriptions = describe_tools(tools)
        max_cycles = max(1, min(self.llm_config.tao_max_cycles, 10))

        for _ in range(max_cycles):
            decision = analyze_tao_action(
                email.body or "",
                evidence,
                sorted(remaining),
                tool_descriptions,
                self.llm_config,
            )
            action = decision.get("action", "final")
            steps.append(
                {
                    "action": action,
                    "reason": str(decision.get("reason", "")),
                }
            )

            if action == "final":
                break
            if action not in remaining:
                if not remaining:
                    break
                action = sorted(remaining)[0]
            tool = registry[action]
            evidence[action] = tool.run(email, llm_config=None)
            remaining.remove(action)

        final = analyze_decision(email.body or "", evidence, self.llm_config)
        evidence["final"] = final
        evidence["tao"] = steps

        scores: dict[str, float] = {}
        for key, data in evidence.items():
            if isinstance(data, dict) and "score" in data:
                scores[key] = float(data.get("score", 0.0))

        risk = float(final.get("risk", 0.0))
        label = str(final.get("label", "benign"))
        return AgentState(email=email, evidence=evidence, scores=scores, risk=risk, label=label)

    @staticmethod
    def _load_configs(config_path: str | Path | None) -> tuple[PolicyConfig, LLMConfig]:
        if not config_path:
            return PolicyConfig(), LLMConfig()

        path = Path(config_path)
        if not path.exists():
            return PolicyConfig(), LLMConfig()

        data = yaml.safe_load(path.read_text()) or {}
        policy = data.get("policy", {})
        threshold = float(policy.get("threshold", 0.7))
        weights = policy.get("weights")
        llm = data.get("llm", {})
        if isinstance(weights, dict):
            return PolicyConfig(threshold=threshold, weights=weights), LLMConfig.from_dict(llm)
        return PolicyConfig(threshold=threshold), LLMConfig.from_dict(llm)
