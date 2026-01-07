from __future__ import annotations

import json

from schemas.evidence_schema import EvidenceStore, HeaderAuthResult, SemanticResult
from agent.explanation import build_explanation


def test_explanation_structure_and_safety() -> None:
    evidence = EvidenceStore(
        header_auth=HeaderAuthResult(
            spf="pass",
            dkim="pass",
            dmarc="pass",
            aligned=True,
            anomalies=[],
        ),
        semantic=SemanticResult(
            intent="benign",
            urgency=0,
            brand_entities=[],
            requested_actions=[],
            confidence=0.4,
        ),
    )
    breakdown = [{"factor": "spf_fail", "value": 0.0, "weight": 12.0, "contribution": 0.0}]
    explanation = build_explanation(evidence, "benign", 5, breakdown)
    payload = explanation.model_dump()

    assert payload["verdict"] == "benign"
    assert "top_signals" in payload
    assert "recommended_action" in payload
    assert "evidence" in payload
    assert "Thought:" not in json.dumps(payload)
