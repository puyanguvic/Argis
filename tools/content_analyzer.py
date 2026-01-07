"""Content-based NLP heuristics for phishing signals."""

from __future__ import annotations

from typing import Dict

from agent.config import LLMConfig
from schemas.email_schema import EmailSchema
from tools.llm_client import analyze_phishing

SUSPICIOUS_PHRASES = [
    "urgent",
    "verify your account",
    "password",
    "wire transfer",
    "immediate action",
    "unusual sign-in",
    "unrecognized device",
    "limited access",
    "account may be permanently restricted",
]
TIME_PRESSURE_PATTERNS = [
    "within 24 hours",
    "within 48 hours",
    "act now",
    "immediately",
]


def analyze_content(email: EmailSchema, llm_config: LLMConfig | None = None) -> Dict[str, object]:
    findings = []
    score = 0.0
    body = (email.body or "").lower()

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in body:
            findings.append(f"phrase:{phrase}")
            score += 0.15
    for phrase in TIME_PRESSURE_PATTERNS:
        if phrase in body:
            findings.append(f"time_pressure:{phrase}")
            score += 0.2

    llm_result = None
    if llm_config and llm_config.enabled:
        llm_result = analyze_phishing(email.body or "", llm_config)
        llm_score = float(llm_result.get("score", 0.0))
        weight = max(0.0, min(1.0, llm_config.llm_weight))
        score = (1.0 - weight) * score + weight * llm_score

    response: Dict[str, object] = {"score": min(score, 1.0), "findings": findings}
    if llm_result is not None:
        response["llm"] = llm_result
    return response
