"""Attachment typing heuristics."""

from __future__ import annotations


def classify_attachment(filename: str) -> str:
    lower = (filename or "").lower().strip()
    if not lower:
        return "unknown"
    risky = (
        ".exe",
        ".msi",
        ".bat",
        ".cmd",
        ".scr",
        ".js",
        ".vbs",
        ".jar",
        ".ps1",
        ".hta",
        ".iso",
        ".zip",
        ".rar",
    )
    if any(lower.endswith(ext) for ext in risky):
        return "high_risk"
    if lower.endswith((".docm", ".xlsm", ".pptm")):
        return "macro_risk"
    return "low_risk"
