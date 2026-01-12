---
layout: default
---

# 术语表（Glossary）

## Email / Threat

- **Phishing**：通过欺骗手段诱导用户点击链接、提交凭据或执行恶意操作的邮件攻击。
- **BEC（Business Email Compromise）**：商业邮件欺诈，常见为冒充高管/供应商诱导转账或更改收款信息。
- **APT**：高级持续性威胁，常见为定向、高质量、低噪音的长期攻击活动。

## Email Authentication

- **SPF**：发件服务器授权校验机制，验证发送 IP 是否被域名授权。
- **DKIM**：基于签名的邮件完整性与域名校验机制。
- **DMARC**：结合 SPF/DKIM 的策略框架，提供对齐（alignment）与处置策略。
- **Aligned（对齐）**：认证结果与 From 域名的一致性。本项目使用简化规则计算（见 `tools_builtin/header_analyzer.py`）。

## System Concepts

- **EmailInput**：标准化邮件输入 schema（`schemas/email_schema.py`）。
- **EvidenceStore**：证据总线，承载所有工具输出（`schemas/evidence_schema.py`）。
- **Tool**：把原始输入转为结构化证据的组件（`tools_builtin/`）。
- **Profile（FAST/STANDARD/DEEP）**：取证深度/成本的路由选择（`engine/router.py`）。
- **Hard Rule**：命中即强制判为 `phishing` 的组合规则（`scoring/rules.py`）。
- **Risk Fusion / Risk Score**：对多维信号加权融合得到 0–100 分（`scoring/fusion.py`）。
- **Verdict**：离散裁决结果：`benign` / `suspicious` / `phishing`。
- **Recommended action**：建议动作：`allow` / `warn` / `quarantine`（`engine/explanation.py`）。
- **Contextual escalation**：上下文升级（FAST → STANDARD），用于对协作/OAuth 低噪音场景补齐证据（`engine/orchestrator.py`）。
- **Degradations**：降级/证据缺失/升级标记列表（`EvidenceStore.degradations`）。

