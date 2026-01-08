# 品牌仿冒检测（Brand Impersonation）

品牌仿冒的目标是“看起来像”可信品牌或组织域名，从而诱导点击/登录/转账。该技能强调**域名相似性 + 认证失败 + 内容意图**的组合证据。

## 关键风险信号

- Lookalike 域名（与品牌词距离极小）
- 同形字/混淆（homoglyph）、punycode（`xn--`）
- From/Reply-To 域名不一致（路由快速特征）
- 与凭据窃取意图同时出现（更高置信）

## 当前实现（离线、确定性）

### 域名风险评估

- 工具：`domain_risk_assess(domains)`（`tools/domain_risk.py`）
- 输出：`DomainRiskResult(items=[DomainRiskItem...])`（`schemas/evidence_schema.py`）
- 机制：
  - 用 Levenshtein 距离与静态品牌词表 `_BRANDS` 比较
  - `distance <= 1` 标记 `brand_similarity`
  - `domain.startswith("xn--")` 标记 `punycode_domain`
  - 简化同形字启发式 `_homoglyph_suspected()`

### 与路由/评分的关系

相关快速特征：

- `from_domain_mismatch` / `reply_to_mismatch`（`agent/router.py`）

相关评分因子（`scoring/fusion.py`）：

- `lookalike_domain`
- `from_domain_mismatch`
- `reply_to_mismatch`
- 认证失败：`spf_fail` / `dkim_fail` / `dmarc_fail`

相关硬规则（`scoring/rules.py`）：

- `spf_fail_lookalike_credential_intent`

## 报告呈现建议

当命中 lookalike/homoglyph/punycode 时，报告应明确：

- 具体可疑域名（`DomainRiskItem.domain`）
- 触发的风险旗标（`risk_flags`）
- 若同时存在凭据意图/认证失败，应提升为高优先级处置

## 可改进点

- 扩展品牌库与组织 allowlist（按租户/行业定制）
- 增强同形字与 punycode 解码能力
- 引入在线域名信誉/注册时间（作为额外证据源，受 sandbox 控制）

