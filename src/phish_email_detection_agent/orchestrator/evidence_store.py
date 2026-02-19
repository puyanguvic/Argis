"""In-memory evidence store with stable evidence IDs and de-duplication."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _stable_fingerprint(*, category: str, payload: dict[str, Any], source: str, tags: tuple[str, ...]) -> str:
    canonical = json.dumps(
        {
            "category": category,
            "payload": payload,
            "source": source,
            "tags": list(tags),
        },
        sort_keys=True,
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    category: str
    payload: dict[str, Any]
    source: str
    tags: tuple[str, ...]
    created_at: str
    fingerprint: str


class EvidenceStore:
    """Simple in-memory evidence graph primitive.

    This is intentionally lightweight and deterministic so it can be used from
    orchestrator layers without introducing storage/runtime dependencies.
    """

    def __init__(self) -> None:
        self._records: list[EvidenceRecord] = []
        self._by_id: dict[str, EvidenceRecord] = {}
        self._id_by_fingerprint: dict[str, str] = {}

    def add(
        self,
        *,
        category: str,
        payload: dict[str, Any],
        source: str = "",
        tags: list[str] | tuple[str, ...] | None = None,
        allow_duplicate: bool = False,
    ) -> EvidenceRecord:
        normalized_category = str(category).strip() or "generic"
        normalized_source = str(source).strip()
        normalized_tags = tuple(sorted({str(item).strip() for item in (tags or []) if str(item).strip()}))
        normalized_payload = payload if isinstance(payload, dict) else {"value": payload}
        fingerprint = _stable_fingerprint(
            category=normalized_category,
            payload=normalized_payload,
            source=normalized_source,
            tags=normalized_tags,
        )
        if not allow_duplicate and fingerprint in self._id_by_fingerprint:
            existing_id = self._id_by_fingerprint[fingerprint]
            return self._by_id[existing_id]

        evidence_id = f"evd_{len(self._records) + 1:04d}"
        record = EvidenceRecord(
            evidence_id=evidence_id,
            category=normalized_category,
            payload=normalized_payload,
            source=normalized_source,
            tags=normalized_tags,
            created_at=_utc_now(),
            fingerprint=fingerprint,
        )
        self._records.append(record)
        self._by_id[evidence_id] = record
        self._id_by_fingerprint[fingerprint] = evidence_id
        return record

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self._by_id.get(str(evidence_id).strip())

    def all(self) -> list[EvidenceRecord]:
        return list(self._records)

    def by_category(self, category: str) -> list[EvidenceRecord]:
        target = str(category).strip()
        return [item for item in self._records if item.category == target]

    def refs(self, *, limit: int = 64) -> list[dict[str, Any]]:
        cap = max(0, int(limit))
        refs: list[dict[str, Any]] = []
        for item in self._records[:cap]:
            refs.append(
                {
                    "evidence_id": item.evidence_id,
                    "category": item.category,
                    "source": item.source,
                    "tags": list(item.tags),
                }
            )
        return refs
