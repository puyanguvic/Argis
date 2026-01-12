---
layout: default
---

# 运维与监控（Operations）

本页列出将系统投入运行时建议监控的指标与操作流程。

## 1) 运行时与稳定性

- `runtime_ms`：p50/p95/p99
- profile 分布：FAST/STANDARD/DEEP
- 工具错误率（未来扩展时）：timeout/exception/egress denied
- 证据缺失率：关键字段为空的占比

## 2) 质量监控

- `phishing` 命中率与后验确认率（人工确认）
- `suspicious` 升级量与处理 SLA
- 误报/漏报样本回收与复盘节奏

## 3) 变更治理

- 权重/阈值/规则更新必须可追溯（见 `governance/`）
- 变更前后用 benchmark scenarios 做回归（见 `evaluation/benchmark_scenarios.md`）
- 保持回滚能力（配置版本化）

## 4) 审计与数据保留

- `run.jsonl` 与事件输出应按隐私政策设定 retention（见 `policies/privacy_policy.md`）
- 对审计数据启用访问控制与审计

