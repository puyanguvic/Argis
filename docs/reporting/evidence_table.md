# 证据表定义（Evidence Table）

证据表用于把复杂检测结果拆成可审计的“证据条目”，用于报告、SIEM 或工单系统。

## 证据条目字段（当前实现）

`agent/report.py` 内部使用 `EvidenceLine` 表达证据条目：

- `section`：证据分类（Sender authentication / URL / Domain / Content / Attachments）
- `severity`：严重度（LOW / MED / HIGH）
- `message`：人类可读描述
- `evidence_id`：稳定编号（示例：`ev-0010`）
- `score_hint`：该条证据的参考贡献（用于排序与解释）

## 证据表使用建议

- `evidence_id` 应与“规则/因子”建立映射，便于审计与治理
- `severity` 不等价于 `risk_score`，更偏“取证强度/告警级别”
- 对于同类证据（如多个 URL），报告可以：
  - 只展示最强的 1–3 条
  - 其余作为附件/折叠项供深度分析

## 与 EvidenceStore 的关系

证据条目应能指回 `EvidenceStore` 的字段：

- Header：`evidence.header_auth`
- URL：`evidence.url_chain`
- Domain：`evidence.domain_risk`
- Content：`evidence.semantic`
- Attachments：`evidence.attachment_scan`

