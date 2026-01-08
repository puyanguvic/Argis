# 证据收集机制

系统的“证据总线”是 `EvidenceStore`（`schemas/evidence_schema.py`）。所有工具输出必须写入该对象，裁决层只依赖证据而不直接依赖原始输入文本。

## EvidenceStore 字段映射

| 字段 | 由谁产生 | 主要用途 |
|---|---|---|
| `header_auth` | `header_auth_check` | 认证失败/不对齐信号 |
| `url_chain` | `url_chain_resolve` | URL 风险旗标、域名提取 |
| `domain_risk` | `domain_risk_assess` | lookalike/homoglyph/punycode |
| `semantic` | `semantic_extract` | intent/urgency/brands/actions |
| `attachment_scan` | `attachment_static_scan` | 宏/可执行扩展名 |
| `quick_features` | Router | 路由与评分输入 |
| `preliminary_score` | Router | FAST/STANDARD/DEEP 选择 |
| `plan` / `path` | Router | 执行计划与 profile |
| `hard_rule_matches` | Policy | 命中的硬规则 code |
| `degradations` | Orchestrator | 降级/升级/缺失证据标记 |

## 工具执行与赋值

工具执行发生在 `agent/orchestrator.py`，并通过 `_assign_observation()` 写入正确字段。

建议扩展时保持：

- 工具输出对象可被 `.model_dump()` 或 JSON 序列化
- `EvidenceStore` 字段为“可选”，允许按 profile 收集部分证据

## 审计：Record & Replay

- 录制：`RunRecorder.record(node_name, input_state, tool_outputs)` 写 JSONL（`agent/recorder.py`）
- 回放：`replay_run()` 合并 JSONL 输出为 `EvidenceStore`（`agent/player.py`）

这使得你可以：

- 在不运行外部工具的情况下复现裁决
- 对比不同配置/规则版本下的行为差异

