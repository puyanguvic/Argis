"""Header-based analysis (SPF/DKIM/From vs Reply-To)."""

from __future__ import annotations

from typing import Dict

from schemas.email_schema import EmailSchema


def analyze_headers(email: EmailSchema) -> Dict[str, object]:
    findings = []
    score = 0.0

    if not email.sender:
        findings.append("missing_sender")
        score += 0.15
    if not email.subject:
        findings.append("missing_subject")
        score += 0.1

    reply_to = email.raw_headers.get("Reply-To")
    if reply_to and email.sender and reply_to != email.sender:
        findings.append("reply_to_mismatch")
        score += 0.4

    return {"score": min(score, 1.0), "findings": findings}
