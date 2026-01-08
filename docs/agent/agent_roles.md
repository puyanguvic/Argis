# Reasoner / Executor / Verifier

虽然当前实现是单进程内的多个函数/模块，但系统在职责上可以拆解为三类角色，便于扩展到更复杂的代理架构。

## 1) Reasoner（规划/路由）

职责：

- 从输入中提取**快速信号**，估计风险与取证成本
- 选择执行路径（FAST/STANDARD/DEEP）
- 生成结构化执行计划 `PlanSpec`

对应实现：

- `engine/router.py`（`quick_features()`、`preliminary_score()`、`plan_routes()`）

## 2) Executor（工具执行/取证）

职责：

- 按计划执行工具，将原始输入转为结构化证据
- 处理执行时的降级、补采与错误（未来扩展）

对应实现：

- `engine/orchestrator.py`（工具执行、上下文升级）
- `tools_builtin/`（各类确定性证据源）

## 3) Verifier（裁决/解释/输出）

职责：

- 基于证据做**硬规则**验证与**风险融合**，输出 verdict
- 输出结构化解释（证据引用 + 评分分解）
- 渲染报告/JSON，便于人读与机读

对应实现：

- `engine/policy.py` + `scoring/`
- `engine/explanation.py` + `schemas/explanation_schema.py`
- `engine/report.py`、`apps/cli/main.py`

## 为什么要拆角色

- **可审计**：规划、取证、裁决各自可被记录与回放
- **可替换**：未来可以用更强的工具替换某一环节而不改裁决契约
- **可控风险**：把“解释/输出”与“工具/外部依赖”解耦，减少不可控因素

