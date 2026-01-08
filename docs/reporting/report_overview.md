# 报告设计理念

报告的目标是“可行动、可解释、可审计”：

- 可行动：给出清晰的处置建议（隔离/告警/允许）
- 可解释：给出 top reasons 与证据细节
- 可审计：能追溯到 `EvidenceStore` 与评分因子

当前仓库提供两种输出：

- **Markdown 报告**：面向人类读者（`agent/report.py`）
- **JSON 输出**：面向系统集成（`agent/cli.py --format json`）

## Markdown 报告结构（当前实现）

`agent/report.py` 输出的报告包含：

1. 标题与概要：
   - Verdict label（ALLOW / ESCALATE / QUARANTINE）
   - Confidence（由分数映射）
   - Trace ID
   - Profile（FAST/STANDARD/DEEP）
2. Top reasons：按严重度与贡献提示排序的三条理由
3. Recommended actions：按 verdict 提供的动作列表
4. Evidence (details)：按类别展开（认证/URL/内容/附件）
5. Runtime：总耗时

## 解释输出（结构化）

结构化解释由 `agent/explanation.py` 生成，适用于：

- API 返回
- SIEM 事件字段
- 审计/回放时的稳定解释

