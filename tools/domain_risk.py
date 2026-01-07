"""Domain risk assessment (deterministic)."""

from __future__ import annotations

from schemas.evidence_schema import DomainRiskItem, DomainRiskResult

_BRANDS = {"microsoft", "paypal", "google", "apple", "amazon", "bank", "dhl", "ups", "fedex"}
_HOMOGLYPH_CHARS = {"0", "1", "3", "5", "7"}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current.append(
                min(
                    prev[j] + 1,
                    current[j - 1] + 1,
                    prev[j - 1] + cost,
                )
            )
        prev = current
    return prev[-1]


def _min_brand_distance(domain: str) -> tuple[int, str]:
    best = 999
    best_brand = ""
    for brand in _BRANDS:
        distance = _levenshtein(domain, brand)
        if distance < best:
            best = distance
            best_brand = brand
    return best, best_brand


def _homoglyph_suspected(domain: str) -> bool:
    return any(char in _HOMOGLYPH_CHARS for char in domain) and any(
        char.isalpha() for char in domain
    )


def domain_risk_assess(domains: list[str]) -> DomainRiskResult:
    """Assess lookalike and homoglyph risk for domains."""

    items: list[DomainRiskItem] = []
    for domain in domains:
        normalized = domain.lower()
        distance, brand = _min_brand_distance(normalized)
        flags: list[str] = []
        if distance <= 1 and brand:
            flags.append("brand_similarity")
        if normalized.startswith("xn--"):
            flags.append("punycode_domain")
        if _homoglyph_suspected(normalized):
            flags.append("homoglyph_suspected")
        items.append(
            DomainRiskItem(
                domain=domain,
                levenshtein_to_brand=distance,
                homoglyph_suspected=_homoglyph_suspected(normalized),
                risk_flags=flags,
            )
        )
    return DomainRiskResult(items=items)
