# 推理约束 & Guardrails

本页定义系统在“推理/输出”层面的约束，目标是在可扩展的同时保证安全、可控与可审计。

## 1) 证据约束（Evidence Constraints）

- 裁决必须来自 `EvidenceStore`：不得凭空新增未观测到的事实。
- 所有风险因素必须可追溯到：
  - 具体工具输出字段（如 `header_auth.dmarc`）
  - 或硬规则 match code（`scoring/rules.py`）
- 解释输出只引用证据键与结构化内容，避免泄露邮件全文。

## 2) 输出约束（Explanation & Report）

- 不输出 chain-of-thought：解释以 `top_signals`、`score_breakdown` 为主（`schemas/explanation_schema.py`）。
- 推荐动作固定在 `allow / warn / quarantine` 三类（`engine/explanation.py`）。
- 人类报告避免过度技术细节，但保留可审计证据编号（`engine/report.py` 内部有 `evidence_id`）。

## 3) 工具约束（Tool Safety）

- 默认离线与确定性：避免因网络/上游波动影响结果稳定性。
- 工具输出必须可序列化：确保 JSONL 录制与回放可靠（`engine/recorder.py`）。
- 工具的异常应被记录为“降级/缺失证据”（建议写入 `evidence.degradations`；当前实现保留字段）。

## 4) 风险控制（避免误判/过判）

- 对证据不足场景优先 `suspicious` + 升级策略，而非强行判 `phishing`。
- 对“协作/OAuth 低噪音”场景采用上下文升级：增加取证深度，不直接加分。
- 通过配置与测试锁定行为：阈值/权重可调，且应有回归测试覆盖（`tests/`）。

