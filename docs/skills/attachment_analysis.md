---
layout: default
---

# 附件风险分析

附件是恶意载荷投递的重要路径。当前实现以“静态元信息”为主：识别宏文档与可执行脚本/二进制的扩展名信号。

## 核心信号

- 宏文档扩展名：`.docm`, `.xlsm`, `.pptm`
- 可执行/脚本扩展名：`.exe`, `.js`, `.vbs`, `.scr`, `.bat`, `.cmd`, `.ps1`

## 当前实现

工具：`attachment_static_scan(attachments)`（`tools_builtin/attachment_analyzer.py`）

- 输入：`EmailInput.attachments`（`schemas/email_schema.py` 的 `AttachmentMeta`）
- 输出：`AttachmentScanResult(items=[AttachmentScanItem...])`
- 行为：
  - 根据文件扩展名设置 `has_macro` / `is_executable`
  - 将扩展名命中写入 `flags`（如 `macro_extension`）

## 与语义/规则的联动

硬规则示例（`scoring/rules.py`）：

- `malware_intent_executable_attachment`
  - 条件：`semantic.intent == "malware_delivery"` 且存在 `is_executable`

融合评分因子（`scoring/fusion.py`）：

- `attachment_macro`
- `attachment_executable`

## 扩展建议

若需要更强的附件能力，建议在隔离环境中新增证据源：

- 解包与内容扫描（OLE/宏标记、脚本关键 API、签名/熵）
- 压缩包链（zip/iso/img）递归提取
- 哈希信誉（内部 IOC / 情报源）

输出应仍然映射为结构化证据，避免直接执行附件内容。

