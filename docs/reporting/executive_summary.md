---
layout: default
---

# 高层摘要结构（Executive Summary）

面向管理层/非技术读者的摘要应回答四个问题：

1. **发生了什么**：这封邮件是否可能是钓鱼/BEC/恶意投递？
2. **有多严重**：风险分数与置信度如何？
3. **为什么这么认为**：最重要的 2–3 条证据是什么？
4. **接下来做什么**：隔离/告警/复核/用户提示等行动建议

## 推荐摘要字段

- Verdict：`ALLOW / ESCALATE / QUARANTINE`
- Risk score：`0–100`
- Confidence：`LOW / MED / HIGH`
- Profile：`FAST / STANDARD / DEEP`
- Top reasons：3 条以内（避免细节淹没重点）
- Recommended actions：2–4 条
- Notes（可选）：
  - “证据收集受限/仅 FAST profile”提示
  - “需要业务方核验”的 BEC 提示

## 与当前实现的映射

- Markdown 报告的头部已经包含上述大部分字段（`engine/report.py`）
- JSON 输出包含 `verdict/risk_score/trace_id/profile/explanation`（`apps/cli/main.py`）

