---
layout: default
---

# URL & 重定向 & 混淆分析

URL 是钓鱼邮件最常见的落地点。该技能关注：URL 是否存在、是否可疑、是否与登录/验证动作相关。

## 核心信号

- URL 存在（扩大攻击面）
- 短链/跳板（隐藏落地页）
- 可疑 TLD（`.zip`/`.click` 等）
- IP 直连（绕过域名信誉）
- URL 中包含登录/验证关键词（`login`, `verify`, `account`…）

## 当前实现

### URL 提取

- `extract_urls([body_text, body_html])`（`tools_builtin/url_utils.py`）
- 简化正则：提取 `http(s)://...` 并做少量尾部标点清理

### URL 解析与词法风险

- `url_chain_resolve(urls)`（`tools_builtin/url_analyzer.py`）
- 输出：`UrlChainResult(chains=[UrlChainItem...])`
- 约束：不进行网络跳转；每个 URL 仅产出“单跳”链（`hops=[input]`）

### 评分与规则

风险融合因子（`scoring/fusion.py`）：

- `url_present`
- `url_login_keywords`
- `url_shortener`
- `url_ip_host`
- `url_suspicious_tld`

硬规则（`scoring/rules.py`）示例：

- `dmarc_fail_reply_to_login_url`

## 报告呈现建议

报告中建议至少展示：

- final URL / final domain（若可得）
- 命中的 URL 风险旗标（shortener/suspicious_tld/login_keywords/ip_host）
- 与认证失败/Reply-To mismatch 的组合解释（若触发硬规则）

## 扩展建议（在线/隔离环境）

可选增加：

- 真实重定向链解析（HEAD/GET，最大跳数）
- 落地页 HTML 摘要（标题、表单、品牌标识、JS 混淆）
- 文件下载与 MIME 检测（只采样，不执行）

这些扩展应在 sandbox 中运行，并将结果作为新证据字段写入 `EvidenceStore`。

