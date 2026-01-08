# 系统总览（Codex-style）

## 一句话概括

本系统是一个“证据驱动”的钓鱼邮件检测代理：**路由规划 → 工具取证 → 规则与评分融合 → 结构化解释与报告**。

协议定义见 `../protocol_v1.md`。

## 核心数据模型

- `EmailInput`：标准化邮件输入（`schemas/email_schema.py`）
- `EvidenceStore`：证据总线（`schemas/evidence_schema.py`）
- `Explanation`：结构化解释（`schemas/explanation_schema.py`）
- `DetectionResult`：检测结果（`engine/state.py`）

## 核心组件

- **Protocol（稳定契约）**：UI 与 Engine 的 Op/Event 协议（`protocol/`）
- **Engine（核心引擎）**：Session/Task/Turn 主循环（`engine/argis.py`）
- **Router（规划器）**：从快速特征与 Header 认证给出 `FAST/STANDARD/DEEP` 路径与工具计划（`engine/router.py`）
- **Orchestrator（编排器）**：按计划执行工具、处理上下文升级、调用 Policy 输出最终结果（`engine/orchestrator.py`）
- **Tools（证据源）**：将原始输入转为结构化证据（`tools_builtin/`）
- **Providers（模型适配）**：模型与执行环境的可插拔适配层（`providers/`）
- **Connectors（系统接入）**：Gmail/IMAP 等外部系统入口（`connectors/`）
- **Policy（裁决层）**：硬规则 + 融合评分 → verdict（`engine/policy.py`、`scoring/`）
- **Apps（入口/UI）**：CLI / Gradio / API（`apps/`）
- **Reporting**：人类可读报告与机器可读 JSON（`engine/report.py`、`apps/cli/main.py`）
- **Audit**：JSONL 录制与回放（`engine/recorder.py`、`engine/player.py`）

## 端到端数据流

```
EmailInput
  └─ Router: quick_features + header_auth_check
        └─ EvidenceStore(plan/path/preliminary_score)
              └─ Orchestrator: execute tools by plan
                    └─ EvidenceStore(tool outputs)
                          └─ Policy: hard_rules + risk_fusion
                                └─ (verdict, score, breakdown)
                                      └─ Explanation + Report/JSON
```

## 路径（Profiles）

系统以“成本/收益”为导向分配取证预算：

- **FAST**：低风险或证据不足时的轻量取证（默认：Header + Semantic）
- **STANDARD**：补齐 URL 证据（默认：Header + Semantic + URL）
- **DEEP**：进一步检查域名相似与附件类型（默认：STANDARD + DomainRisk + AttachmentScan）

路径选择与工具集合在 `configs/profiles/balanced.yaml` 中配置（对应 `engine/config.py`）。

## 可追溯性与复现

- 每个节点/工具输出可记录到 JSONL（`--record run.jsonl`）。
- 可通过 `phish-agent replay --record run.jsonl` 回放并重新计算 verdict（不再运行工具）。
