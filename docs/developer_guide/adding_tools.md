# 如何接入新工具（Adding Tools）

本项目把工具定义为“把输入变成结构化证据”的纯函数/组件。

## 1) 设计输出 schema

- 在 `schemas/evidence_schema.py` 增加结果模型（Pydantic）
- 在 `EvidenceStore` 增加可选字段

## 2) 实现工具

- 在 `tools_builtin/` 新增模块（例如 `tools_builtin/whois_lookup.py`）
- 输入尽量只接受必要字段（域名/URL/附件元信息），避免传递正文全文
- 输出为 schema 模型或 dict，确保可 JSON 序列化

## 3) 接入执行计划

当前实现用字符串名称选择工具（`PlanSpec.tools`），映射在：

- `engine/orchestrator.py` → `_build_tool_map()`
- `engine/orchestrator.py` → `_assign_observation()`

同时更新：

- `configs/profiles/balanced.yaml`：把工具名加入 profile 的 tools 列表

## 4) 评分与报告联动

- 在 `scoring/fusion.py` 增加新因子并赋权
- 在 `engine/report.py` 增加新的 EvidenceLine（可选）

## 5) 工具安全（尤其是在线工具）

- 必须有超时与最大输出大小限制
- 必须有明确的网络 egress allowlist（若需要网络）
- 输出应可审计并避免泄露敏感内容
