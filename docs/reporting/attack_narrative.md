---
layout: default
---

# 攻击链推理（Attack Narrative）

“攻击链叙事”用于把证据组织成一段可读的故事线，帮助人工分析与响应决策。它不是模型思维链，也不应包含未经证据支持的推测。

## 推荐叙事模板

1. **身份与可信度**
   - 认证结果（SPF/DKIM/DMARC）是否失败？是否不对齐？
   - From/Reply-To 是否不一致？
2. **诱饵与意图**
   - 内容意图（credential / oauth / invoice / malware）
   - 是否存在紧迫语气与指令动作（click/download/reply）
3. **落地与载荷**
   - URL 是否指向可疑域名/短链/可疑 TLD？
   - 是否存在宏/可执行附件？
4. **潜在影响**
   - 凭据泄露、权限授予、资金损失或恶意执行的风险
5. **处置建议**
   - 隔离/告警/复核与用户提示

## 当前实现状态

仓库当前提供的是：

- Top reasons（最多 3 条）
- 分类证据列表

（见 `engine/report.py`），尚未单独生成“叙事段落”。如需叙事输出，建议：

- 基于 `EvidenceStore` + `score_breakdown` 生成可模板化 narrative
- 保证每句叙事可回指到证据字段或硬规则 code

