# 审计与回放（Audit & Traceability）

审计能力是证据优先系统的核心：你不仅要知道“判了什么”，还要能回答“为什么这样判、当时收集了哪些证据”。

## 1) Trace ID

`engine/orchestrator.py` 会基于 `sender/subject/received_ts` 生成 `trace_id`（哈希截断），用于关联事件与日志。

## 2) JSONL 录制

`RunRecorder`（`engine/recorder.py`）记录：

- `timestamp`
- `node_name`（router/tool/final）
- `input_state_hash`（对输入状态做 hash）
- `tool_outputs`（工具输出或裁决摘要）

注意：`tool_outputs` 可能包含 URL/域名等信息，应按隐私政策保护（见 `policies/privacy_policy.md`）。

## 3) 回放与再裁决

`engine/player.py` 会：

- 读取 JSONL
- 合并工具输出为 `EvidenceStore`
- 用当前配置重算 verdict/score

用途：

- 复现问题与回归对比（无需外部依赖）
- 比较配置/规则/模型更新的影响

## 4) 生产化建议

- 为事件输出增加 `schema_version` 与 `config_version/config_hash`
- 为规则与模型更新维护 changelog
- 对审计日志启用访问控制、加密与保留策略

