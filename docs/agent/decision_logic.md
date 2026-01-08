# 决策与风险评分逻辑

本页描述 verdict 是如何从证据中产生的。核心思路：**先路由后取证，先证据后裁决**。

## 1) 路由（FAST / STANDARD / DEEP）

路由逻辑在 `engine/router.py`：

1. 计算 `QuickFeatures`：
   - `from_domain_mismatch`
   - `reply_to_mismatch`
   - `has_urls`
   - `suspicious_subject`
2. 解析 `HeaderAuthResult`（SPF/DKIM/DMARC + aligned）
3. 合成 `preliminary_score`（0–100）
4. 按阈值选择路径：
   - `< t_fast` → `FAST`
   - `>= t_deep` → `DEEP`
   - else → `STANDARD`

默认阈值与工具集合见 `configs/profiles/balanced.yaml`。

## 2) 上下文升级（FAST → STANDARD）

当同时满足以下条件时触发（`engine/orchestrator.py`）：

- 当前路径为 `FAST`
- 发件人域名不在 allowlist（`AgentConfig.allowlist_domains`）
- `semantic.intent` 命中 `contextual_escalation.intents`
- `semantic.brand_entities` 与 `contextual_escalation.brands` 有交集，或正文命中 `contextual_escalation.keywords`

触发效果：

- 只升级取证深度（补执行 STANDARD 工具，如 URL 分析）
- 不直接增加风险分数

## 3) 裁决（Hard Rules + Risk Fusion）

裁决入口：`engine/policy.py`。

### 3.1 硬规则（Hard Rules）

实现：`scoring/rules.py`。

- 规则是“组合条件”，用于覆盖评分不足但证据组合强的情况
- 命中任意规则时：
  - `verdict` 强制为 `phishing`
  - `risk_score` 至少为 `block_threshold`

### 3.2 融合评分（Risk Fusion）

实现：`scoring/fusion.py`。

- 将因子 `value`（0–1 或 0–1 区间）乘以 `weight` 得到 `contribution`
- 累加并截断到 0–100
- 输出 `breakdown`（包含每个因子的 value/weight/contribution）

默认权重在 `configs/profiles/balanced.yaml`（可覆盖 `DEFAULT_WEIGHTS`）。

### 3.3 分数映射（Verdict Mapping）

- `score >= block_threshold` → `phishing`
- `score >= escalate_threshold` → `suspicious`
- else → `benign`

阈值由 `configs/profiles/balanced.yaml` 配置（`thresholds.block_threshold`、`thresholds.escalate_threshold`）。

## 4) 解释输出（为什么这样判）

`engine/explanation.py` 生成 `Explanation`：

- 若命中硬规则：`top_signals` 优先输出 `hard_rule:<code>`
- 否则：按贡献度排序输出 `score_factor:<factor>`
- `evidence` 字段只引用结构化证据（不输出正文原文）

