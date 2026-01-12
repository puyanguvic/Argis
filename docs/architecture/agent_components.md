---
layout: default
---

# Agent 内部模块划分

本页从代码结构角度解释系统的模块边界与依赖关系，便于扩展与维护。

## 模块地图

### 1) `protocol/`（UI <-> Engine 稳定契约）

- `protocol/op.py`：Op（ConfigureSession / UserInput / Interrupt / Approval）
- `protocol/events.py`：EventMsg（AgentMessage / TaskComplete / Error 等）
- `protocol/types.py`：SessionConfig / Artifact / Bookmark
- `protocol/serde.py`：JSON framing 与版本兼容

### 2) `engine/`（核心引擎）

- `engine/argis.py`：Session/Task/Turn 主循环
- `engine/session.py`：Session 状态
- `engine/task.py`：Task 生命周期
- `engine/turn.py`：Turn 执行与输入处理
- `engine/orchestrator.py`：主编排器（路由、执行工具、上下文升级、调用裁决）
- `engine/router.py`：路由/计划（FAST/STANDARD/DEEP）
- `engine/policy.py`：裁决入口（硬规则 + 融合评分）
- `engine/explanation.py`：结构化解释（证据引用 + 评分分解）
- `engine/report.py`：Markdown 报告渲染
- `engine/recorder.py`：JSONL 录制（审计）
- `engine/player.py`：回放 JSONL（重算裁决，不执行工具）

### 3) `apps/`（入口/UI）

- `apps/cli/main.py`：CLI 命令 `detect` / `replay`
- `apps/demo/gradio_app.py`：Gradio 演示

### 2) `schemas/`（输入/证据/解释的契约）

- `schemas/email_schema.py`：`EmailInput`、`AttachmentMeta`
- `schemas/evidence_schema.py`：`EvidenceStore` 与各类工具结果模型
- `schemas/explanation_schema.py`：`Explanation` 输出模型

### 4) `tools_builtin/`（确定性证据源）

- `tools_builtin/parser.py`：原始邮件解析为 `EmailInput`
- `tools_builtin/header_analyzer.py`：SPF/DKIM/DMARC 抽取
- `tools_builtin/url_analyzer.py`：URL 解析与词法风险（离线）
- `tools_builtin/domain_risk.py`：域名相似/同形字检测
- `tools_builtin/content_analyzer.py`：意图/紧迫度/品牌实体抽取（规则式）
- `tools_builtin/attachment_analyzer.py`：附件元信息静态扫描
- `tools_builtin/tool_registry.py`：可选的工具注册表（为未来集成做准备）

### 5) `providers/`（模型适配层）

- `providers/model/base.py`：ModelProvider interface
- `providers/model/ollama.py`：Ollama 实现（可插拔）

### 6) `connectors/`（外部系统接入）

- `connectors/gmail/`：Gmail OAuth + API 入口
- `connectors/imap/`：IMAP 接入

### 7) `scoring/`（风险融合与硬规则）

- `scoring/fusion.py`：加权融合得到 0–100 分与分解
- `scoring/rules.py`：硬规则（命中则强制 `phishing`）

## 依赖方向（重要）

推荐保持单向依赖，避免循环：

- `tools_builtin/` 与 `scoring/` 依赖 `schemas/`
- `engine/` 依赖 `protocol/`、`schemas/`、`tools_builtin/`、`scoring/`
- `apps/` 依赖 `protocol/`（通过 Op/Event 驱动 engine）
- `schemas/` 不依赖上层模块

## 扩展点

- 新增证据源：在 `tools_builtin/` 新增工具 + 在 `EvidenceStore` 增加字段 + 在编排器/注册表接入
- 新增评分因子：在 `scoring/fusion.py` 增加 factor + 在 `configs/profiles/balanced.yaml` 配置权重
- 新增硬规则：在 `scoring/rules.py` 增加 match code（并补测试）
