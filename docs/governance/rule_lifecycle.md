---
layout: default
---

# 规则生命周期（Rule Lifecycle）

规则与权重会直接影响拦截/告警行为，因此需要“可控变更”。

## 1) 变更类型

- 路由阈值：影响取证成本与证据完备度（`configs/profiles/balanced.yaml` 的 `router.*`）
- 评分权重：影响分数与 top_signals（`scoring/fusion.py` + `configs/profiles/balanced.yaml`）
- 硬规则：影响强制拦截（`scoring/rules.py`）

## 2) 变更流程（建议）

1. 需求与风险评估：明确要降低哪类误报/漏报
2. 提交变更：
   - 配置更新或代码更新
   - 更新文档（对应 skill/因子）
3. 回归验证：
   - 跑基准场景与单元测试（`tests/` + `evaluation/benchmark_scenarios.md`）
4. 发布策略：
   - 灰度（小流量/低风险租户）
   - 监控关键指标（误拦截、漏报、SLA）
5. 复盘与固化：
   - 记录变更原因、样本与效果

## 3) 规则编码与可追溯性

- 硬规则应有稳定 `match code`（见 `scoring/rules.py`）
- 报告中的 `evidence_id` 建议与规则/因子建立映射（见 `reporting/evidence_table.md`）

