# 设计目标 & 非目标

## 设计目标（Goals）

1. **证据优先（Evidence-first）**
   - 所有工具输出汇聚到 `EvidenceStore`（`schemas/evidence_schema.py`）。
   - 评分与规则基于证据做融合，输出包含可解释的分解。

2. **默认确定性与离线（Deterministic Offline-by-default）**
   - 默认不需要网络访问即可运行核心流程。
   - 便于测试、可复现、可审计。

3. **分层职责清晰（Router / Tools / Policy）**
   - Router 负责路径选择与计划（`agent/router.py`）。
   - Tools 负责把原始输入转为结构化证据（`tools/`）。
   - Policy 负责规则与评分融合后裁决（`agent/policy.py`、`scoring/`）。

4. **可审计与可回放（Audit & Replay）**
   - 每一步工具输出可录制为 JSONL（`agent/recorder.py`）。
   - 支持回放并重新计算 verdict（`agent/player.py`）。

5. **输出面向“行动”（Actionable Outputs）**
   - 给出 `allow / warn / quarantine` 的建议动作（`agent/explanation.py`、`agent/report.py`）。
   - 报告同时服务人类读者与机器系统（CLI JSON 输出）。

## 非目标（Non-goals）

- **不追求“全自动完美判定”**：对低证据、强语境邮件优先走 `suspicious` + 人工升级策略。
- **不做在线情报查询**：如 WHOIS/DNS/URL 真实跳转、VT/URLScan 等均不在默认路径内（可作为未来工具扩展）。
- **不执行/不动态沙箱**：附件不解包、不运行，不做动态行为分析。
- **不输出推理过程（chain-of-thought）**：解释只包含证据引用与评分分解。

## 成功标准（How we know it works）

- 对常见钓鱼/仿冒/短链/可疑 TLD/宏附件等场景，能稳定产出高风险分数与可审计证据。
- 对协作/OAuth 诱导等低噪音场景，能触发“上下文升级”以收集更多证据，而不随意加分。
- 规则与权重可通过 `configs/default.yaml` 调参，且能被测试覆盖（`tests/`）。

