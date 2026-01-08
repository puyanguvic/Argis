# Protocol v1 (UI <-> Engine)

本协议定义 UI 与 Engine 的稳定交互边界：**Op → Engine → EventMsg**。核心目标是让 UI/入口与 Engine 解耦，使引擎长期演进时无需重构入口层。

## 设计原则

- **稳定契约**：Protocol 尽量少变，Engine 与 UI 可独立迭代。
- **可扩展**：新增 UI、Connector、Model Provider 不影响核心引擎目录。
- **双队列模型**：SubmissionQueue (SQ) / EventQueue (EQ)，支持异步处理与回放。

## 核心概念

### Session

一次会话的配置上下文，包含 profile/provider/connector 等设置。

### Task

一次用户输入形成一个 Task，可由多个 Turn 组成（例如多轮工具调用）。

### Turn

一次模型/工具驱动的执行循环，最终发出 TurnComplete 与 TaskComplete。

## 队列模型

```
UI                 Engine
 |  Op  -> SQ  ->  [handle Op]  ->  EQ  -> EventMsg |
```

UI 只负责发送 Op 并消费 EventMsg。

## Ops

- `ConfigureSession`：设置 profile/config/provider/connector
- `UserInput`：提交输入（邮件 JSON / raw email / 录制回放）
- `Interrupt`：中断当前任务（预留）
- `Approval`：审批响应（预留）

## EventMsg

- `SessionConfigured`：Session 创建完成
- `AgentMessage`：状态/提示信息
- `ApprovalRequest`：需要 UI 审批的操作
- `TurnComplete`：一次 Turn 完成（带 bookmark）
- `TaskComplete`：任务完成（携带 artifacts）
- `Error`：错误事件

## Artifacts

当前引擎输出的 artifacts：

- `detection_result`：结构化结果（verdict / risk_score / explanation / evidence）
- `report_md`：Markdown 报告文本

## 版本策略

Protocol v1 保持字段向前兼容。新增字段只增不删；兼容解析在 `protocol/serde.py` 中完成。
