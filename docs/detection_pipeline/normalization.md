# 去混淆 / 标准化（Normalization）

标准化的目标是：把攻击者的“格式/编码/混淆”手段还原成更稳定的信号，从而提升工具的可重复性与跨样本一致性。

## 当前实现（最小化）

仓库当前在以下位置做了轻量标准化：

- URL 提取后去掉常见尾部标点（`tools/url_utils.py`）
- 语义抽取将 subject/body 合并并统一为小写（`tools/content_analyzer.py`）
- URL 域名提取使用 `tldextract`（`tools/url_analyzer.py`）

## 推荐的标准化清单（可逐步引入）

### 文本标准化

- HTML → 纯文本（去 script/style、保留可读文本）
- Unicode 归一化（NFKC）与零宽字符清理
- 常见混淆替换：`hxxp`、`[.]`、空格插入域名等

### URL 标准化

- 解码 URL 编码与 HTML entity
- 统一解析 userinfo/端口、去掉跟踪参数（可选）
- 规范化 punycode（显示人类可读形式 + 保留原始）

### 域名标准化

- 统一为小写
- 提取 registrable domain（eTLD+1）
- 组织 allowlist/内部域名识别（决定 external/internal）

标准化应尽量发生在证据源之前，或作为独立证据源写入 `EvidenceStore`，避免隐式改变裁决逻辑。

