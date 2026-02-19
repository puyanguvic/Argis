"""Workflow orchestration layer.

Exports are loaded lazily to avoid import-time cycles between orchestrator and
pipeline modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from phish_email_detection_agent.orchestrator.build import create_agent
    from phish_email_detection_agent.orchestrator.evaluator import OfflineEvaluation, OfflineEvaluator
    from phish_email_detection_agent.orchestrator.evidence_store import EvidenceRecord, EvidenceStore
    from phish_email_detection_agent.orchestrator.pipeline import AgentService
    from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy
    from phish_email_detection_agent.orchestrator.skill_router import SkillExecutionPlan, SkillRouter
    from phish_email_detection_agent.orchestrator.stages import (
        EvidenceBuilder,
        EvidenceStage,
        JudgeEngine,
        PipelineExecutor,
        PipelineRuntime,
    )
    from phish_email_detection_agent.orchestrator.tool_executor import ToolExecutionResult, ToolExecutor
    from phish_email_detection_agent.orchestrator.validator import OnlineValidator, ValidationIssue

__all__ = [
    "create_agent",
    "AgentService",
    "PipelinePolicy",
    "EvidenceRecord",
    "EvidenceStore",
    "SkillExecutionPlan",
    "SkillRouter",
    "EvidenceBuilder",
    "EvidenceStage",
    "PipelineExecutor",
    "JudgeEngine",
    "PipelineRuntime",
    "ToolExecutionResult",
    "ToolExecutor",
    "OnlineValidator",
    "ValidationIssue",
    "OfflineEvaluation",
    "OfflineEvaluator",
]


def __getattr__(name: str) -> Any:
    if name == "create_agent":
        from phish_email_detection_agent.orchestrator.build import create_agent

        return create_agent
    if name == "AgentService":
        from phish_email_detection_agent.orchestrator.pipeline import AgentService

        return AgentService
    if name == "PipelinePolicy":
        from phish_email_detection_agent.orchestrator.pipeline_policy import PipelinePolicy

        return PipelinePolicy
    if name in {"EvidenceRecord", "EvidenceStore"}:
        from phish_email_detection_agent.orchestrator.evidence_store import EvidenceRecord, EvidenceStore

        return {"EvidenceRecord": EvidenceRecord, "EvidenceStore": EvidenceStore}[name]
    if name in {"SkillExecutionPlan", "SkillRouter"}:
        from phish_email_detection_agent.orchestrator.skill_router import SkillExecutionPlan, SkillRouter

        return {"SkillExecutionPlan": SkillExecutionPlan, "SkillRouter": SkillRouter}[name]
    if name in {"EvidenceBuilder", "EvidenceStage", "PipelineExecutor", "JudgeEngine", "PipelineRuntime"}:
        from phish_email_detection_agent.orchestrator.stages import (
            EvidenceBuilder,
            EvidenceStage,
            JudgeEngine,
            PipelineExecutor,
            PipelineRuntime,
        )

        return {
            "EvidenceBuilder": EvidenceBuilder,
            "EvidenceStage": EvidenceStage,
            "PipelineExecutor": PipelineExecutor,
            "JudgeEngine": JudgeEngine,
            "PipelineRuntime": PipelineRuntime,
        }[name]
    if name in {"ToolExecutionResult", "ToolExecutor"}:
        from phish_email_detection_agent.orchestrator.tool_executor import ToolExecutionResult, ToolExecutor

        return {"ToolExecutionResult": ToolExecutionResult, "ToolExecutor": ToolExecutor}[name]
    if name in {"OnlineValidator", "ValidationIssue"}:
        from phish_email_detection_agent.orchestrator.validator import OnlineValidator, ValidationIssue

        return {"OnlineValidator": OnlineValidator, "ValidationIssue": ValidationIssue}[name]
    if name in {"OfflineEvaluation", "OfflineEvaluator"}:
        from phish_email_detection_agent.orchestrator.evaluator import OfflineEvaluation, OfflineEvaluator

        return {"OfflineEvaluation": OfflineEvaluation, "OfflineEvaluator": OfflineEvaluator}[name]
    raise AttributeError(name)
