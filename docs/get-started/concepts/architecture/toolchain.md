---
title: Toolchain and External Signals
redirect_from:
  - /architecture/toolchain.html
---

# Toolchain and external signals

The default toolchain is **offline, deterministic, and reproducible**. Each tool returns structured outputs into `EvidenceStore` for scoring and rules.

## Built-in tools (deterministic)

### 1) Header authentication: `header_auth_check`

- Location: `tools_builtin/header_analyzer.py`
- Input: `raw_headers`
- Output: `HeaderAuthResult(spf, dkim, dmarc, aligned, anomalies)`
- Typical use: treat auth failures as high-weight signals or combine into hard rules.

### 2) Semantic intent: `semantic_extract`

- Location: `tools_builtin/content_analyzer.py`
- Input: `subject`, `body_text`, `body_html`
- Output: `SemanticResult(intent, urgency, brand_entities, requested_actions, confidence)`
- Typical use: detect credential theft/payment/malware/OAuth intent; also triggers contextual escalation.

### 3) URL analysis: `url_chain_resolve`

- Location: `tools_builtin/url_analyzer.py`
- Input: URL list (extracted with `tools_builtin/url_utils.extract_urls()`)
- Output: `UrlChainResult` (final_domain, shortener, suspicious_tld, login_keywords, etc.)
- Constraint: offline parsing only; no network redirect resolution.

### 4) Domain risk: `domain_risk_assess`

- Location: `tools_builtin/domain_risk.py`
- Input: domain list (from URLs or sender domain)
- Output: `DomainRiskResult(items=[DomainRiskItem...])`
- Typical use: detect lookalike/homoglyph/punycode for rules and scoring.

### 5) Attachment static scan: `attachment_static_scan`

- Location: `tools_builtin/attachment_analyzer.py`
- Input: `attachments` metadata
- Output: `AttachmentScanResult(items=[AttachmentScanItem...])`
- Constraint: no unpacking/execution/sandboxing; metadata and extension checks only.

## External signals (future extensions)

If you add external signals, keep them as evidence sources with stable schemas:

- Domain: WHOIS/age, DNS, reputation, allowlists
- URL: redirect chains, content type, download behavior
- Reputation: threat intel feeds (internal IOCs, vendor feeds)
- Account: sender history, org graph, known contacts

You can swap implementations via `tools_builtin/tool_registry.py` or the tool map in `engine/orchestrator.py`.
