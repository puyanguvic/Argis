# 邮件头取证（Header Forensics）

Header 取证用于评估“发件人身份是否可信”，以及是否存在伪造/未对齐等迹象。

## 核心信号

- SPF/DKIM/DMARC：pass/fail/none
- 对齐（aligned）：From 域与认证结果是否一致（简化）
- 异常（anomalies）：缺失 Header 或缺失认证结果

## 当前实现

工具：`header_auth_check(raw_headers)`（`tools_builtin/header_analyzer.py`）

- 使用正则抽取 `spf|dkim|dmarc=(pass|fail|none)`
- `aligned` 规则（简化）：
  - DMARC pass，或 SPF pass 且 DKIM pass
- `anomalies`：
  - `missing_headers`
  - `missing_auth_results`

## 与路由/评分的关系

- Router 会先执行 Header 检查，并把结果计入 `preliminary_score`（`engine/router.py`）
- 融合评分因子：`spf_fail`、`dkim_fail`、`dmarc_fail`（`scoring/fusion.py`）

## 报告建议

对于认证失败/不对齐邮件，建议在“Top reasons / Evidence”中明确指出：

- 失败项（SPF/DKIM/DMARC）
- 不对齐（aligned=false）
- 同时出现 URL 登录关键词或域名仿冒时，提升优先级

