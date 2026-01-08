# 评估指标（Precision / Recall / Risk）

本项目不仅关心分类准确率，也关心“风险分数是否可用”与“取证成本是否合理”。

## 1) 分类指标

- Precision / Recall / F1（按 `benign/suspicious/phishing` 或二分类）
- Confusion matrix（重点关注 `phishing` 的漏报）

## 2) 风险分数指标（Risk score quality）

- 分数校准（calibration）：分数与真实风险概率的对应关系
- 分层一致性：分数越高，证据强度是否越强、误报率是否越低
- Top signals 稳定性：同类攻击是否输出一致的 top_signals

## 3) 路由与成本指标

- Profile 分布：FAST/STANDARD/DEEP 占比是否符合预期
- 运行时：`runtime_ms` 分位数（p50/p95/p99）
- 证据缺失率：`EvidenceStore` 关键字段为空的比例（按 profile）

## 4) 人工流程指标（对业务更重要）

- `suspicious` 升级量与人工处理时长
- 升级后的确认率（真正恶意占比）
- 误拦截成本（被隔离但最终 benign 的比例）

