# Phish Email Detection Agent Docs

本目录是 `Phish Email Detection Agent` 的产品级与工程级文档集合：从威胁背景、系统架构、检测流水线、报告输出，到安全/隐私/合规与运维治理。

本项目的核心原则：

- **Evidence-first**：先收集结构化证据（`EvidenceStore`），再融合评分与规则，最后输出结论与建议。
- **Deterministic by default**：默认离线、确定性工具链；模型（如未来引入）只作为“证据来源”，不直接裁决。
- **No chain-of-thought**：解释输出以证据引用与评分分解为主（见 `schemas/explanation_schema.py`）。

## 文档导航

### 1) Introduction

- [问题定义与背景](introduction/problem_statement.md)
- [威胁全景：Phishing / BEC / APT](introduction/threat_landscape.md)
- [设计目标与非目标](introduction/design_goals.md)

### 2) Architecture

- [系统总览（Codex-style）](architecture/system_overview.md)
- [Agent 组件划分](architecture/agent_components.md)
- [端到端工作流](architecture/workflow_pipeline.md)
- [工具链与外部信号](architecture/toolchain.md)
- [执行模型（单次任务 / sandbox）](architecture/execution_model.md)

### 3) Agent

- [角色划分：Reasoner / Executor / Verifier](agent/agent_roles.md)
- [决策逻辑与风险评分](agent/decision_logic.md)
- [推理约束与 Guardrails](agent/reasoning_policy.md)
- [已知失败模式与风险](agent/failure_modes.md)

### 4) Skills（检测“技能/剧本”）

- [概览：Skill / Playbook 机制](skills/overview.md)
- [品牌仿冒检测](skills/brand_impersonation.md)
- [BEC 检测](skills/bec_detection.md)
- [URL 分析：重定向/混淆](skills/url_analysis.md)
- [邮件头取证](skills/header_forensics.md)
- [附件风险分析](skills/attachment_analysis.md)

### 5) Detection Pipeline

- [输入接入：EML / MSG / API](detection_pipeline/ingestion.md)
- [解析：MIME / Header / Body](detection_pipeline/parsing.md)
- [标准化：去混淆 / 归一化](detection_pipeline/normalization.md)
- [证据收集机制](detection_pipeline/evidence_collection.md)
- [风险融合与评分](detection_pipeline/risk_scoring.md)

### 6) Reporting

- [报告设计理念](reporting/report_overview.md)
- [高层摘要结构](reporting/executive_summary.md)
- [证据表定义](reporting/evidence_table.md)
- [攻击链推理叙事](reporting/attack_narrative.md)
- [响应建议](reporting/recommendation.md)
- [机器可读输出：JSON / API](reporting/machine_output.md)

### 7) Policies

- [安全与访问控制](policies/security_policy.md)
- [隐私与脱敏](policies/privacy_policy.md)
- [合规（SOC2 / GDPR 视角）](policies/compliance.md)
- [人工升级规则](policies/escalation_policy.md)

### 8) Evaluation

- [评估指标：Precision / Recall / Risk](evaluation/evaluation_metrics.md)
- [基准测试场景](evaluation/benchmark_scenarios.md)
- [已知局限](evaluation/known_limitations.md)

### 9) Deployment

- [部署模型：Local / Cloud / Hybrid](deployment/deployment_models.md)
- [配置：YAML / ENV](deployment/configuration.md)
- [集成：SIEM / Email Gateway](deployment/integration.md)
- [运维与监控](deployment/operations.md)

### 10) Developer Guide

- [代码结构](developer_guide/code_structure.md)
- [如何新增 Skill](developer_guide/adding_skills.md)
- [如何接入新工具](developer_guide/adding_tools.md)
- [调试与 Trace](developer_guide/debugging.md)

### 11) Governance

- [模型更新策略](governance/model_updates.md)
- [规则生命周期](governance/rule_lifecycle.md)
- [审计与可追溯性](governance/audit_and_traceability.md)

### 12) Glossary

- [术语表](glossary.md)

## 从这里开始

如果你是第一次阅读，建议顺序：

1. `introduction/problem_statement.md`
2. `architecture/system_overview.md`
3. `detection_pipeline/evidence_collection.md`
4. `reporting/report_overview.md`

