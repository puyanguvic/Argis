# Agent 内部模块划分

本页从代码结构角度解释系统的模块边界与依赖关系，便于扩展与维护。

## 模块地图

### 1) `agent/`（编排与对外接口）

- `agent/orchestrator.py`：主编排器（路由、执行工具、上下文升级、调用裁决）
- `agent/router.py`：路由/计划（FAST/STANDARD/DEEP）
- `agent/policy.py`：裁决入口（硬规则 + 融合评分）
- `agent/explanation.py`：结构化解释（证据引用 + 评分分解）
- `agent/report.py`：Markdown 报告渲染
- `agent/recorder.py`：JSONL 录制（审计）
- `agent/player.py`：回放 JSONL（重算裁决，不执行工具）
- `agent/cli.py`：CLI 命令 `detect` / `replay`

### 2) `schemas/`（输入/证据/解释的契约）

- `schemas/email_schema.py`：`EmailInput`、`AttachmentMeta`
- `schemas/evidence_schema.py`：`EvidenceStore` 与各类工具结果模型
- `schemas/explanation_schema.py`：`Explanation` 输出模型

### 3) `tools/`（确定性证据源）

- `tools/parser.py`：原始邮件解析为 `EmailInput`
- `tools/header_analyzer.py`：SPF/DKIM/DMARC 抽取
- `tools/url_analyzer.py`：URL 解析与词法风险（离线）
- `tools/domain_risk.py`：域名相似/同形字检测
- `tools/content_analyzer.py`：意图/紧迫度/品牌实体抽取（规则式）
- `tools/attachment_analyzer.py`：附件元信息静态扫描
- `tools/tool_registry.py`：可选的工具注册表（为未来集成做准备）

### 4) `scoring/`（风险融合与硬规则）

- `scoring/fusion.py`：加权融合得到 0–100 分与分解
- `scoring/rules.py`：硬规则（命中则强制 `phishing`）

## 依赖方向（重要）

推荐保持单向依赖，避免循环：

- `tools/` 与 `scoring/` 依赖 `schemas/`
- `agent/` 依赖 `schemas/`、`tools/`、`scoring/`
- `schemas/` 不依赖上层模块

## 扩展点

- 新增证据源：在 `tools/` 新增工具 + 在 `EvidenceStore` 增加字段 + 在编排器/注册表接入
- 新增评分因子：在 `scoring/fusion.py` 增加 factor + 在 `configs/default.yaml` 配置权重
- 新增硬规则：在 `scoring/rules.py` 增加 match code（并补测试）

