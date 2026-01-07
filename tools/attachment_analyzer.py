"""Attachment-based analysis."""

from __future__ import annotations

from typing import Dict

from schemas.email_schema import EmailSchema

SUSPICIOUS_EXTENSIONS = {".exe", ".js", ".vbs", ".scr", ".zip"}


def analyze_attachments(email: EmailSchema) -> Dict[str, object]:
    findings = []
    score = 0.0

    for name in email.attachments:
        lower = name.lower()
        for ext in SUSPICIOUS_EXTENSIONS:
            if lower.endswith(ext):
                findings.append(f"ext:{ext}")
                score += 0.3
                break

    return {"score": min(score, 1.0), "findings": findings}
