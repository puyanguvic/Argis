"""Online output guardrails for orchestrator final results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_ALLOWED_VERDICTS = {"benign", "phishing", "suspicious"}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    severity: str = "warning"


class OnlineValidator:
    """Lightweight guardrails that do not depend on model/tool internals."""

    def validate_triage_result(self, result: dict[str, Any]) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        verdict = str(result.get("verdict", "")).strip().lower()
        if verdict not in _ALLOWED_VERDICTS:
            issues.append(
                ValidationIssue(
                    code="invalid_verdict",
                    severity="error",
                    message=f"Unexpected verdict value: {verdict!r}.",
                )
            )

        raw_score = result.get("risk_score", 0)
        try:
            score = int(raw_score)
        except (TypeError, ValueError):
            issues.append(
                ValidationIssue(
                    code="invalid_risk_score_type",
                    severity="error",
                    message=f"Risk score must be int-like, got {type(raw_score).__name__}.",
                )
            )
            score = -1
        if score < 0 or score > 100:
            issues.append(
                ValidationIssue(
                    code="invalid_risk_score_range",
                    severity="error",
                    message=f"Risk score out of range [0, 100]: {score}.",
                )
            )

        indicators = result.get("indicators")
        if verdict == "phishing" and (not isinstance(indicators, list) or not indicators):
            issues.append(
                ValidationIssue(
                    code="missing_indicators",
                    message="Phishing verdict should include at least one indicator.",
                )
            )

        evidence = result.get("evidence")
        if verdict == "phishing" and not isinstance(evidence, dict):
            issues.append(
                ValidationIssue(
                    code="missing_evidence",
                    message="Phishing verdict should include evidence payload.",
                )
            )
        return issues
