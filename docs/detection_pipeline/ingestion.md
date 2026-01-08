# 输入接入：EML / MSG / API

本页描述系统如何接收邮件输入并转为统一的 `EmailInput`。

## 1) 推荐入口：EmailInput JSON

CLI 默认从 JSON 文件读取 `EmailInput`：

```bash
phish-agent detect --input examples/email_sample.json
```

相关实现：

- `agent/cli.py`：读取 JSON 并校验为 `EmailInput`
- `schemas/email_schema.py`：输入契约

适用于：

- 作为服务/API 的上游（由接入层完成解析与脱敏）
- 与 SIEM/网关集成（以结构化事件方式传输）

## 2) 原始邮件文本（.eml）

`AgentOrchestrator.detect_raw(raw_email)` 会调用解析器把 raw email 转为 `EmailInput`：

- 解析器：`tools/parser.py`（基于 Python `email` 标准库）
- Gradio demo：`apps/gradio_demo/app.py` 会接收 raw email 文本

注意：当前解析器不提取附件，仅提取正文与 headers。

## 3) MSG/平台 API（现状与建议）

当前仓库未实现 `.msg` 解析或对接邮件平台 API；建议在接入层完成：

- MSG → MIME / headers / body 的解码与归一化
- 附件元信息填充（filename/mime/size/sha256/flags）
- 组织上下文补齐（allowlist、内部域名、联系人关系等）

最终统一为 `EmailInput` 进入检测流水线。

