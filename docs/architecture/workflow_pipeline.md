# End-to-end 工作流

本页描述一次检测任务从输入到输出的完整流程，以及 FAST/STANDARD/DEEP 的运行差异。

## 1) 输入进入系统

系统支持两类入口：

- **JSON 输入**：CLI 读取 `EmailInput` JSON（`agent/cli.py`）
- **原始邮件文本**：通过 `parse_raw_email()` 解析为 `EmailInput`（`tools/parser.py`），示例见 Gradio demo

## 2) Router：快速特征 + 初筛评分

`agent/router.py` 会做两件事：

1. `header_auth_check(raw_headers)`：抽取 SPF/DKIM/DMARC 与对齐情况
2. `quick_features(email)`：从 From/Reply-To、URL 是否存在、主题关键词等生成快速特征

然后将两者合成为 `preliminary_score`（0–100），并根据阈值选择路径：

- `prelim < t_fast` → `FAST`
- `prelim >= t_deep` → `DEEP`
- 否则 → `STANDARD`

阈值与每条路径的工具集合由 `configs/default.yaml` 配置（对应 `agent/config.py`）。

## 3) Orchestrator：按计划执行工具

`agent/orchestrator.py` 按 `plan.tools` 顺序执行工具，并将工具输出写入 `EvidenceStore`：

- `header_auth_check` → `evidence.header_auth`
- `semantic_extract` → `evidence.semantic`
- `url_chain_resolve` → `evidence.url_chain`
- `domain_risk_assess` → `evidence.domain_risk`
- `attachment_static_scan` → `evidence.attachment_scan`

## 4) FAST 的“上下文升级”（Contextual Escalation）

部分协作/OAuth 类邮件可能缺少传统恶意信号，但仍需要更多证据。系统引入“上下文升级”：

- 仅当 Router 选择 `FAST` 且 `semantic.intent` 命中配置的协作意图，并且品牌/关键词匹配时
- 将 profile 从 `FAST` 升级为 `STANDARD`，补执行 `STANDARD` 工具（通常是 URL 分析）
- 该升级会写入 `evidence.degradations`，用于审计（见 `agent/orchestrator.py`）

注意：上下文升级是**取证路由信号**，不直接为风险分数加分。

## 5) Policy：硬规则 + 风险融合

`agent/policy.py` 调用：

1. `apply_hard_rules(evidence)`：若命中则强制 `phishing`（`scoring/rules.py`）
2. `compute_risk_score(evidence, weights)`：加权融合得到分数与分解（`scoring/fusion.py`）
3. `map_score_to_verdict(score, thresholds)`：阈值映射为离散 verdict

## 6) 输出：解释 + 报告 / JSON

输出包含：

- `Explanation`：`top_signals` + `recommended_action` + `evidence` 引用 + `score_breakdown`
- Markdown 报告：`agent/report.py`
- 机器可读 JSON：`phish-agent detect --format json`（`agent/cli.py`）

## 7) 审计：Record & Replay

- `--record run.jsonl` 会记录 router、每个工具与最终裁决输出（`agent/recorder.py`）
- `phish-agent replay --record run.jsonl` 可离线回放并重算裁决（`agent/player.py`）

