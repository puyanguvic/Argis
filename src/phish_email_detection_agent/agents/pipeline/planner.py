"""Planning stage for modular phishing analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

from phish_email_detection_agent.agents.pipeline.router import map_route_to_path
from phish_email_detection_agent.domain.evidence import EvidencePack


@dataclass
class ExecutionPlan:
    has_content: bool
    route: str
    path: str
    should_invoke_judge: bool
    reasons: list[str] = field(default_factory=list)


class Planner:
    def plan(
        self,
        *,
        evidence_pack: EvidencePack,
        has_content: bool,
        can_call_remote: bool,
    ) -> ExecutionPlan:
        route = str(evidence_pack.pre_score.route)
        reasons = list(evidence_pack.pre_score.reasons)
        if not reasons:
            reasons = ["no_strong_signals"]
        return ExecutionPlan(
            has_content=has_content,
            route=route,
            path=map_route_to_path(route),
            should_invoke_judge=has_content and can_call_remote,
            reasons=reasons,
        )

