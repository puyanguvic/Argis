# Tools / External signals

本项目默认工具链强调“离线、确定性、可复现”。工具返回结构化结果并写入 `EvidenceStore`，供评分与规则使用。

## 当前内置工具（Deterministic）

### 1) Header 认证：`header_auth_check`

- 位置：`tools_builtin/header_analyzer.py`
- 输入：`raw_headers`
- 输出：`HeaderAuthResult(spf, dkim, dmarc, aligned, anomalies)`
- 典型用途：将邮件认证失败作为中高权重信号，或与其他证据组合触发硬规则

### 2) 内容语义：`semantic_extract`

- 位置：`tools_builtin/content_analyzer.py`
- 输入：`subject`, `body_text`, `body_html`
- 输出：`SemanticResult(intent, urgency, brand_entities, requested_actions, confidence)`
- 典型用途：识别凭据窃取/付款/恶意投递/OAuth 等意图；也用于“上下文升级”

### 3) URL 分析：`url_chain_resolve`

- 位置：`tools_builtin/url_analyzer.py`
- 输入：URL 列表（可由 `tools_builtin/url_utils.extract_urls()` 从正文抽取）
- 输出：`UrlChainResult`（包含 final_domain、shortener、suspicious_tld、login_keywords 等）
- 约束：默认不进行网络跳转解析；每个 URL 只做离线解析与词法检查

### 4) 域名风险：`domain_risk_assess`

- 位置：`tools_builtin/domain_risk.py`
- 输入：域名列表（由 URL 或 sender 域名收集）
- 输出：`DomainRiskResult(items=[DomainRiskItem...])`
- 典型用途：识别 lookalike / homoglyph / punycode，支持硬规则与评分因子

### 5) 附件静态扫描：`attachment_static_scan`

- 位置：`tools_builtin/attachment_analyzer.py`
- 输入：`attachments` 元信息
- 输出：`AttachmentScanResult(items=[AttachmentScanItem...])`
- 约束：不解包/不执行/不做动态沙箱；仅基于扩展名与 flags

## External signals（未来扩展方向）

如需接入外部信号，推荐将其设计为“证据源”，并保持输出 schema 稳定：

- 域名：WHOIS/注册时间、DNS、信誉、组织 allowlist
- URL：真实跳转链、重定向次数、内容类型、下载行为
- 信誉：威胁情报（内部 IOC、商业情报源）
- 账号：发件人历史行为、组织关系图、已知联系人

建议通过 `tools_builtin/tool_registry.py` 或在 `engine/orchestrator.py` 的 tool map 处替换实现。

