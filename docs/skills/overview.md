---
layout: default
---

# Skill / Playbook 机制说明

本项目将“技能（Skill）/剧本（Playbook）”理解为：**围绕某类攻击目标的一组取证步骤（tools）+ 证据结构（schemas）+ 裁决策略（policy）**。

当前仓库的实现更接近“固定的 playbook 集合”（由 Router 选择 FAST/STANDARD/DEEP），但文档仍以 Skill 的方式组织，便于后续扩展为可组合的技能库。

## Skill 的最小构成

一个可落地的 Skill 通常包含：

1. **触发条件**：何时运行该技能（路由阈值、上下文升级、手工触发）
2. **证据源**：要执行哪些工具、收集哪些字段（写入 `EvidenceStore`）
3. **评分/规则**：该技能贡献哪些评分因子或硬规则
4. **输出呈现**：报告中应如何解释与行动建议

## 当前系统中 Skill 与代码的映射

| Skill | 主要证据 | 主要实现 |
|---|---|---|
| Header Forensics | SPF/DKIM/DMARC、aligned、anomalies | `tools_builtin/header_analyzer.py`, `engine/router.py` |
| URL Analysis | final_domain、shortener、suspicious_tld、login_keywords、ip_host | `tools_builtin/url_analyzer.py`, `tools_builtin/url_utils.py` |
| Brand Impersonation | lookalike/homoglyph/punycode、品牌近似 | `tools_builtin/domain_risk.py`, `scoring/rules.py` |
| Attachment Analysis | macro/executable 扩展名 | `tools_builtin/attachment_analyzer.py` |
| BEC Detection | Reply-To mismatch、付款/转账意图、紧迫度 | `engine/router.py`, `tools_builtin/content_analyzer.py` |

## 组合与路由（FAST/STANDARD/DEEP）

- FAST：最小取证集（通常用于低风险或资源受限）
- STANDARD：补齐 URL 证据
- DEEP：补齐域名相似与附件风险

路径与工具集合可在 `configs/profiles/balanced.yaml` 中配置（见 `engine/config.py`）。

## 未来扩展建议

若要引入新的 Skill（例如“账号接管检测”“历史行为异常”），推荐遵循：

- 先定义输出证据结构（扩展 `schemas/evidence_schema.py`）
- 将外部信号适配为确定性“证据源”接口（写入 `EvidenceStore`）
- 在 `scoring/fusion.py` 增加因子并在配置里赋权（或在 `scoring/rules.py` 增加硬规则）

