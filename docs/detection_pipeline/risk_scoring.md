---
layout: default
---

# 风险融合与评分

本页描述风险分数如何计算，以及如何通过配置与扩展控制系统行为。

## 1) 融合评分（Risk Fusion）

实现：`compute_risk_score(evidence, weights)`（`scoring/fusion.py`）

- 每个因子生成 `value`（0/1 或 0–1）
- 贡献：`contribution = weight * value`
- 总分：对所有因子贡献求和，并截断到 0–100
- 输出：`(risk_score: int, breakdown: list[...])`

## 2) 默认因子与来源

下表对应 `scoring/fusion.py` 中的 factors（权重可在 `configs/profiles/balanced.yaml` 修改）：

- Header：
  - `spf_fail` / `dkim_fail` / `dmarc_fail`：来自 `evidence.header_auth`
- Router 快速特征：
  - `reply_to_mismatch` / `from_domain_mismatch` / `url_present`：来自 `evidence.quick_features`
- URL：
  - `url_login_keywords` / `url_shortener` / `url_ip_host` / `url_suspicious_tld`：来自 `evidence.url_chain`
- 域名：
  - `lookalike_domain`：来自 `evidence.domain_risk`
- 语义：
  - `semantic_credential_intent`：`semantic.intent == "credential_theft"`
  - `semantic_urgency`：`semantic.urgency_level / 3.0`
  - `collaboration_oauth_intent`：`semantic.intent` 命中协作意图集合
- 附件：
  - `attachment_macro` / `attachment_executable`：来自 `evidence.attachment_scan`

## 3) verdict 映射与阈值

实现：`map_score_to_verdict()`（`scoring/fusion.py`）

- `score >= block_threshold` → `phishing`
- `score >= escalate_threshold` → `suspicious`
- else → `benign`

阈值配置：`configs/profiles/balanced.yaml` → `thresholds.*`

## 4) 硬规则（Hard Rules）覆盖

实现：`apply_hard_rules()`（`scoring/rules.py`）

- 若命中任意规则：
  - verdict 强制为 `phishing`
  - risk_score 至少为 `block_threshold`

## 5) 如何调参

优先在 `configs/profiles/balanced.yaml` 调整：

- Router：`t_fast` / `t_deep` 与 tools 集合（影响取证成本与证据完备度）
- Weights：控制各信号贡献
- Thresholds：控制最终 `benign/suspicious/phishing` 的分界

建议用 `tests/` 添加/更新回归样本，避免调参引入意外行为改变。

