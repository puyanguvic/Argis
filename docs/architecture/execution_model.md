# 单次任务执行模型（sandbox）

本页描述一次检测任务的执行边界、预算与失败处理方式。当前代码实现是“单进程编排 + 确定性工具”，但文档以可扩展的 sandbox 模型来约束未来集成。

## 执行边界

- 默认无网络访问：URL/域名工具不进行在线解析（`tools_builtin/url_analyzer.py`）。
- 工具应被视为**纯函数**：输入为 `EmailInput` 或其派生数据，输出为可序列化的结构化对象。
- 所有中间结果进入 `EvidenceStore`，用于审计与回放（`schemas/evidence_schema.py`）。

## 预算与超时

Router 在 `PlanSpec` 中给出：

- `budget_ms`：整体预算（逻辑预算，用于未来扩展）
- `timeout_s`：单次执行超时（逻辑预算，用于未来扩展）
- `fallback`：降级策略（默认 `STANDARD`）

当前实现未强制中断工具执行，但保留该结构以支持未来的并发/隔离执行（见 `engine/router.py`、`engine/config.py`）。

## 执行路径与降级（Degradations）

- 正常情况下按 `plan.tools` 顺序执行。
- 当出现“上下文升级”（FAST → STANDARD）时，系统会：
  - 写入 `evidence.degradations += ["profile_escalated_contextual_signal"]`
  - 扩展 `plan.tools` 并补执行缺失工具（`engine/orchestrator.py`）

在未来引入外部工具/网络情报时，建议把以下信息也写入 `degradations`：

- 超时、配额耗尽、上游不可用
- sandbox 拒绝（网络/文件权限）
- 结果不完整（partial evidence）

## 审计与回放

- `RunRecorder` 将每个节点输出记录为 JSONL，包含 `node_name` 与输入状态 hash（`engine/recorder.py`）
- `replay_run()` 从 JSONL 合并出 `EvidenceStore` 并重算 verdict（`engine/player.py`）

审计目标：

- **可解释**：能回答“为什么判这个结果”
- **可复现**：同一证据与配置应产生同一裁决
- **可追责**：能定位某个工具输出/规则更新导致的行为变化

