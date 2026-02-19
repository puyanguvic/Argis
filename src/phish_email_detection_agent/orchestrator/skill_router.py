"""Skill-oriented route selection for predefined workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy
from phish_email_detection_agent.orchestrator.verdict_routing import map_route_to_path


@dataclass
class SkillExecutionPlan:
    has_content: bool
    route: str
    path: str
    should_invoke_judge: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class SkillRouter:
    """Routes execution within predefined skill workflows."""

    def _sample_allow_route(self, *, evidence_pack: EvidencePack, policy: PipelinePolicy) -> bool:
        sample_rate = float(policy.judge_allow_sample_rate)
        if sample_rate <= 0:
            return False
        fingerprint = "|".join(
            [
                str(evidence_pack.email_meta.message_id),
                str(evidence_pack.email_meta.sender),
                str(evidence_pack.email_meta.subject),
                str(evidence_pack.email_meta.date),
                str(evidence_pack.pre_score.risk_score),
                ",".join(evidence_pack.pre_score.reasons[:4]),
            ]
        )
        token = f"{policy.judge_allow_sample_salt}|{fingerprint}"
        bucket = int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:8], 16) / float(0xFFFFFFFF)
        return bucket < sample_rate

    def _should_invoke_judge_for_route(
        self,
        *,
        route: str,
        evidence_pack: EvidencePack,
        policy: PipelinePolicy,
    ) -> bool:
        clean_route = str(route or "").strip().lower()
        if clean_route in {"review", "deep"}:
            return True
        if clean_route != "allow":
            return True
        if policy.judge_allow_mode == "always":
            return True
        if policy.judge_allow_mode == "sampled":
            return self._sample_allow_route(evidence_pack=evidence_pack, policy=policy)
        return False

    def plan(
        self,
        *,
        evidence_pack: EvidencePack,
        has_content: bool,
        can_call_remote: bool,
        pipeline_policy: PipelinePolicy | None = None,
    ) -> SkillExecutionPlan:
        active_policy = (pipeline_policy or PipelinePolicy()).normalized()
        route = str(evidence_pack.pre_score.route)
        reasons = list(evidence_pack.pre_score.reasons)
        if not reasons:
            reasons = ["no_strong_signals"]
        should_invoke_judge = has_content and can_call_remote and self._should_invoke_judge_for_route(
            route=route,
            evidence_pack=evidence_pack,
            policy=active_policy,
        )
        return SkillExecutionPlan(
            has_content=has_content,
            route=route,
            path=map_route_to_path(route),
            should_invoke_judge=should_invoke_judge,
            reasons=reasons,
        )
