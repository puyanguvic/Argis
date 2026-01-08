# 已知失败模式 & 风险

本页列出当前实现的主要边界与可能的误判来源，并给出缓解建议。

## 1) Header 解析的局限

- `tools/header_analyzer.py` 使用简化正则抽取 `spf|dkim|dmarc=(pass|fail|none)`：
  - 可能漏掉复杂的 `Authentication-Results` 变体
  - 不解析多次 Received 链路、ARC、align 细节
- 缓解：接入更完整的 Header 解析器，并将输出映射为 `HeaderAuthResult`

## 2) URL 分析默认不做真实跳转

- `tools/url_analyzer.py` 不发起网络请求：
  - 无法发现多跳重定向、短链落地页、下载行为
- 缓解：新增可选在线工具（受 sandbox 控制），把“跳转链/落地页摘要”作为新证据源

## 3) 域名相似检测的覆盖有限

- `tools/domain_risk.py` 的品牌词表 `_BRANDS` 有限且静态
- 同形字检测是启发式（字符集合），对 Unicode 同形字覆盖不足
- 缓解：引入更全面的品牌库/组织 allowlist、punycode 解码与更强的同形字库

## 4) 语义抽取为规则式启发

- `tools/content_analyzer.py` 基于关键词做 intent/urgency 判定：
  - 对高质量 APT 文案、跨语言、行业术语可能召回不足
  - 对模板化邮件可能误触发
- 缓解：将语义模型作为“证据源”接入，但保持裁决仍由 Policy 完成

## 5) 附件分析只看元信息

- `tools/attachment_analyzer.py` 仅根据扩展名识别宏/可执行
- 无法识别：
  - 双扩展名、内嵌脚本、压缩包链、内容型宏等
- 缓解：增加附件解包/静态特征提取（在隔离环境中执行），仍以结构化证据输出

## 6) 上下文缺失导致的 BEC 难题

- BEC 很依赖“组织关系/历史对话/财务流程”
- 当前 `EmailInput` 未包含组织通讯录、历史线程、内部身份图
- 缓解：通过集成层提供更多上下文证据（如“是否新联系人/是否首次收款”），再进入 `EvidenceStore`

