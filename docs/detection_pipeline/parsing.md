---
layout: default
---

# MIME / Header / Body 解析

本页解释 raw email → `EmailInput` 的解析逻辑与边界。

## 当前实现

解析器：`parse_raw_email(raw_email: str) -> EmailInput`（`tools_builtin/parser.py`）

主要步骤：

1. `email.message_from_string()` 解析为 `Message`
2. 提取正文：
   - `text/plain` → `body_text`
   - `text/html` → `body_html`
3. 汇总 headers：
   - 将 `msg.items()` 拼接为多行字符串 `raw_headers`
4. 读取常用字段：
   - `Subject`, `From`, `Reply-To`, `Date`
5. 从正文提取 URL：
   - `extract_urls([body_text, body_html])`（`tools_builtin/url_utils.py`）

## 已知边界

- 字符集/编码处理较简化：用 `decode(errors="ignore")`
- 不解析附件：`attachments=[]`
- 对复杂 MIME 结构（inline/quoted-printable）可能提取不完整

## 建议的增强方向

在保持 `EmailInput` 契约稳定的前提下，可在接入层增强：

- 更完整的 charset/transfer-encoding 处理
- HTML → text 的可读化转换与去噪
- 附件提取与哈希计算（sha256）
- Header 的结构化解析（Authentication-Results、ARC、Received 链等）

