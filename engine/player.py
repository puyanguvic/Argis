"""Replay a recorded run without tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engine.config import AgentConfig
from engine.explanation import build_explanation
from engine.policy import PolicyEngine
from engine.state import DetectionResult
from schemas.evidence_schema import (
    AttachmentScanResult,
    DomainRiskResult,
    EvidenceStore,
    HeaderAuthResult,
    PlanSpec,
    QuickFeatures,
    SemanticResult,
    UrlChainResult,
)


def _load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def _merge_evidence(entries: list[dict[str, Any]]) -> EvidenceStore:
    evidence = EvidenceStore()
    for entry in entries:
        outputs = entry.get("tool_outputs") or {}
        node_name = entry.get("node_name")
        if node_name == "router":
            if "quick_features" in outputs:
                evidence.quick_features = QuickFeatures.model_validate(outputs.get("quick_features"))
            evidence.preliminary_score = outputs.get("preliminary_score")
            evidence.path = outputs.get("path")
            if "plan" in outputs and outputs.get("plan") is not None:
                evidence.plan = PlanSpec.model_validate(outputs.get("plan"))
        elif node_name == "header_auth_check":
            evidence.header_auth = HeaderAuthResult.model_validate(outputs)
        elif node_name == "semantic_extract":
            evidence.semantic = SemanticResult.model_validate(outputs)
        elif node_name == "url_chain_resolve":
            evidence.url_chain = UrlChainResult.model_validate(outputs)
        elif node_name == "domain_risk_assess":
            evidence.domain_risk = DomainRiskResult.model_validate(outputs)
        elif node_name == "attachment_static_scan":
            evidence.attachment_scan = AttachmentScanResult.model_validate(outputs)
    return evidence


def replay_run(path: str | Path, config: AgentConfig | None = None) -> DetectionResult:
    """Replay a recorded run and recompute the verdict."""

    config = config or AgentConfig()
    entries = _load_jsonl(path)
    evidence = _merge_evidence(entries)

    policy = PolicyEngine(config)
    verdict, risk_score, breakdown = policy.decide(evidence)

    explanation = build_explanation(evidence, verdict, risk_score, breakdown)
    return DetectionResult(
        email=None,
        evidence=evidence,
        verdict=verdict,
        risk_score=risk_score,
        explanation=explanation,
        trace_id="replay",
        runtime_ms=0,
    )
