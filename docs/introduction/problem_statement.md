# 问题定义与威胁背景

## 我们要解决什么

钓鱼邮件（Phishing）与相关的邮件型社会工程（如 BEC、OAuth 同意诱导、恶意附件投递）具有以下典型特点：

- **低成本、高频率**：规模化投递，变体多，规避规则快。
- **强语境依赖**：是否“异常”高度依赖组织内外部关系、业务流程与上下文。
- **信号分散**：风险信号存在于 Header 认证、域名/URL、内容意图、附件类型等多个维度。
- **误报成本高**：误拦截影响业务；漏报造成凭据泄露、资金损失与横向移动。

因此，本项目的目标不是“靠单一模型下结论”，而是构建一个**证据优先（evidence-first）**的检测代理：在给定一封邮件输入的情况下，收集结构化证据、量化风险并输出可审计的结果。

## 输入与输出（系统边界）

### 输入（EmailInput）

系统最小可用输入是标准化后的 `EmailInput`（见 `schemas/email_schema.py`），主要字段包括：

- `raw_headers`：原始 Header（用于 SPF/DKIM/DMARC 等认证结果抽取）
- `subject` / `sender` / `reply_to`
- `body_text` / `body_html`
- `urls`（可选；为空时会从正文提取）
- `attachments`：附件元信息（当前为静态特征；不解包、不执行）
- `received_ts`

### 输出（DetectionResult）

系统输出 `DetectionResult`（见 `agent/state.py`），核心包括：

- `verdict`：`benign` / `suspicious` / `phishing`
- `risk_score`：0–100
- `evidence`：`EvidenceStore`（见 `schemas/evidence_schema.py`）
- `explanation`：结构化解释（见 `schemas/explanation_schema.py`）
- `trace_id`：可追踪标识（基于输入字段哈希）

## 约束与假设

- **默认离线**：URL 解析与域名风险评估采用确定性、无网络访问的策略（示例工具在 `tools/`）。
- **证据可审计**：工具输出聚合到 `EvidenceStore`；可通过 JSONL 录制与回放实现审计（`agent/recorder.py`、`agent/player.py`）。
- **解释非“思维链”**：解释输出引用证据键与评分分解，不输出模型推理过程（`agent/explanation.py`）。

## 术语

- **证据（Evidence）**：来自工具的结构化结果（HeaderAuth、URL Chain、Domain Risk、Semantic、Attachment Scan 等）。
- **硬规则（Hard Rules）**：命中后强制判为 `phishing` 的组合条件（`scoring/rules.py`）。
- **融合评分（Risk Fusion）**：将多维信号按权重合成为 0–100 分（`scoring/fusion.py`）。

