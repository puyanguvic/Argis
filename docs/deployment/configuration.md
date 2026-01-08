# 配置：YAML / ENV

系统配置的目标是：在不改代码的情况下调整路由、权重与阈值，并能做到版本可追溯。

## 1) YAML 配置（当前实现）

入口配置：`configs/app.yaml`，用于选择 profile/provider/connector。

默认 profile：`configs/profiles/balanced.yaml`，由 `AgentOrchestrator` 加载（`engine/orchestrator.py`）。
兼容路径：若 profile 配置不存在，将回退到 `configs/default.yaml`。

provider/connector 示例：

- `configs/providers/ollama.yaml`
- `configs/connectors/gmail.yaml`
- `configs/connectors/imap.yaml`

主要配置块（对应 `engine/config.py`）：

- `router`：`t_fast/t_deep`、各 profile 的 tools、预算与 fallback
- `thresholds`：`block_threshold/escalate_threshold`
- `scoring.weights`：评分因子权重
- `allowlist_domains`：组织内部域名 allowlist（用于 external 判断）
- `contextual_escalation`：协作/OAuth 的上下文升级触发条件

## 2) ENV（建议，用于扩展）

当前实现未依赖环境变量；若未来引入在线工具/密钥，建议：

- 用 ENV 或 secret manager 注入（避免写入仓库）
- 对敏感字段做日志脱敏

## 3) 配置版本与回滚（建议）

生产环境建议把以下信息随事件输出一起记录：

- `config_version`（或 git sha）
- `config_hash`（对 YAML 规范化后 hash）

这样可以对比不同配置下的误报/漏报变化，并快速回滚。
