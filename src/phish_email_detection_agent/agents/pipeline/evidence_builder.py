"""Evidence builder stage wrapper."""

from __future__ import annotations

from typing import Any, Callable

from phish_email_detection_agent.domain.evidence import EvidencePack


BuildEvidenceFn = Callable[[Any, Any], tuple[EvidencePack, dict[str, Any]]]


class EvidenceBuilder:
    def __init__(self, build_fn: BuildEvidenceFn) -> None:
        self._build_fn = build_fn

    def build(self, email: Any, service: Any) -> tuple[EvidencePack, dict[str, Any]]:
        return self._build_fn(email, service)

