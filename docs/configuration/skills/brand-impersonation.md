---
title: Brand Impersonation Detection
redirect_from:
  - /skills/brand-impersonation.html
---

# Brand impersonation detection

Brand impersonation aims to look like a trusted brand or organization to trigger clicks, logins, or transfers. This skill emphasizes **domain similarity + auth failures + intent**.

## Key risk signals

- Lookalike domains (small edit distance to brand terms)
- Homoglyph/punycode (e.g., `xn--`)
- From/Reply-To domain mismatch (router quick features)
- Credential-theft intent combined with lookalikes

## Current implementation (offline, deterministic)

### Domain risk assessment

- Tool: `domain_risk_assess(domains)` (`tools_builtin/domain_risk.py`)
- Output: `DomainRiskResult(items=[DomainRiskItem...])` (`schemas/evidence_schema.py`)
- Mechanism:
  - Levenshtein distance against static brand list `_BRANDS`
  - `distance <= 1` → `brand_similarity`
  - `domain.startswith("xn--")` → `punycode_domain`
  - heuristic homoglyph detection `_homoglyph_suspected()`

### Routing/scoring integration

Quick features:

- `from_domain_mismatch` / `reply_to_mismatch` (`engine/router.py`)

Fusion factors (`scoring/fusion.py`):

- `lookalike_domain`
- `from_domain_mismatch`
- `reply_to_mismatch`
- auth failures: `spf_fail` / `dkim_fail` / `dmarc_fail`

Hard rules (`scoring/rules.py`):

- `spf_fail_lookalike_credential_intent`

## Reporting guidance

When a lookalike/homoglyph/punycode is detected, highlight:

- the suspicious domain (`DomainRiskItem.domain`)
- triggered risk flags (`risk_flags`)
- elevate priority if combined with credential intent or auth failures

## Improvements

- Expand brand catalogs and tenant/org allowlists.
- Strengthen homoglyph detection and punycode decoding.
- Add online domain reputation/age as optional evidence (sandbox-controlled).
