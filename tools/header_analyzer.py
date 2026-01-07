"""Header authentication analysis."""

from __future__ import annotations

import re

from schemas.evidence_schema import HeaderAuthResult

_AUTH_PATTERN = re.compile(r"(spf|dkim|dmarc)=(pass|fail|none)", re.IGNORECASE)


def _extract_auth_results(raw_headers: str) -> dict[str, str]:
    results: dict[str, str] = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for match in _AUTH_PATTERN.finditer(raw_headers or ""):
        key = match.group(1).lower()
        value = match.group(2).lower()
        results[key] = value
    return results


def header_auth_check(raw_headers: str) -> HeaderAuthResult:
    """Extract SPF/DKIM/DMARC verdicts and anomalies from raw headers."""

    results = _extract_auth_results(raw_headers or "")
    anomalies: list[str] = []

    if raw_headers is None or not raw_headers.strip():
        anomalies.append("missing_headers")
    if all(value == "none" for value in results.values()):
        anomalies.append("missing_auth_results")

    aligned = results["dmarc"] == "pass" or (
        results["spf"] == "pass" and results["dkim"] == "pass"
    )

    return HeaderAuthResult(
        spf=results["spf"],
        dkim=results["dkim"],
        dmarc=results["dmarc"],
        aligned=aligned,
        anomalies=anomalies,
    )
