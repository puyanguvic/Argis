# JSON / API 输出规范

本页定义机器可读输出的字段与稳定性原则，便于与 SIEM、SOAR、邮件网关等系统集成。

## CLI JSON 输出（当前实现）

命令：

```bash
phish-agent detect --input examples/email_sample.json --format json
```

输出结构由 `apps/cli/main.py` 生成，字段包括：

- `verdict`：`benign` / `suspicious` / `phishing`
- `risk_score`：0–100
- `trace_id`：运行标识
- `profile`：FAST/STANDARD/DEEP
- `explanation`：`Explanation` 的序列化结果

## Explanation 结构

`schemas/explanation_schema.py`：

- `verdict`
- `risk_score`
- `top_signals`：`hard_rule:<code>` 或 `score_factor:<factor>`
- `recommended_action`：`allow` / `warn` / `quarantine`
- `evidence`：结构化证据引用（不包含邮件全文）
- `score_breakdown`：每个评分因子的 value/weight/contribution

## 稳定性与版本策略（建议）

为避免集成方受破坏性变更影响，建议遵循：

- `verdict/risk_score/recommended_action` 语义稳定
- 新增字段只增不删，尽量不改字段含义
- 对 break change 引入 `schema_version`（当前实现未加，可在集成层补充）

## SIEM/SOAR 集成建议字段（可选）

除了 CLI 当前输出，集成层可补充以下字段（来自上游系统）：

- `message_id`, `tenant_id`, `user_id`
- `sender_domain`, `reply_to_domain`
- `urls`（原始与规范化后的）
- `attachments`（sha256、mime、size）
- `received_ts`
- `pipeline_config_hash`（配置版本/规则版本）

这些字段与检测输出一起写入事件流，便于回溯与横向分析。

