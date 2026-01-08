# 威胁全景：Phishing / BEC / APT 邮件

本页给出邮件威胁的“地图”，用于指导工具与规则的取证重点。系统不依赖单一信号，而是将威胁拆解为可观测的证据维度。

## 1) 典型攻击类型

### 凭据窃取（Credential Phishing）

- 诱导用户点击登录链接、输入密码或 MFA 码
- 常见手法：品牌仿冒域名、短链、可疑 TLD、IP 直连、登录关键词

### BEC / 财务欺诈（Business Email Compromise）

- 冒充管理层/供应商，诱导转账或修改收款信息
- 常见手法：Reply-To 伪造、显示名欺骗、语气紧迫、发票/付款关键词

### OAuth / 协作诱导（Consent & Collaboration Abuse）

- 诱导用户授予第三方应用权限、添加委派访问、共享邮箱访问等
- 特点：传统恶意信号可能较少，但**语义意图**与“协作品牌”高度相关
- 本项目将这类信号用于**上下文升级（FAST → STANDARD）**，而非直接加分（见 `agent/orchestrator.py`）

### 恶意附件投递（Malware Delivery）

- 通过宏文档、脚本或可执行文件传播恶意软件
- 常见手法：宏启用诱导（Enable Content）、脚本附件、压缩包链路（本项目默认不解包）

### APT/定向攻击（Targeted Spear Phishing）

- 高质量文案、组织上下文强、可能使用被入侵的合法账号/域名
- 传统硬信号弱，需依赖多维证据融合与人工复核流程

## 2) 可观测证据维度（对应系统工具）

- **Header 认证**：SPF/DKIM/DMARC 结果、对齐情况、异常（`tools/header_analyzer.py`）
- **URL/域名**：短链、可疑 TLD、IP Host、登录关键词、（可扩展）跳转链（`tools/url_analyzer.py`）
- **域名相似性**：品牌近似、同形字、punycode（`tools/domain_risk.py`）
- **语义意图**：credential / invoice / oauth / malware 等意图与紧迫度（`tools/content_analyzer.py`）
- **附件元信息**：宏扩展名、可执行扩展名（`tools/attachment_analyzer.py`）

## 3) 防守视角：为什么要“证据优先”

- **可解释**：将风险分解为明确的证据项 + 权重贡献，便于人工审计与改规则。
- **可控**：默认离线/确定性，避免“外部依赖抖动”影响生产裁决。
- **可演进**：未来引入外部情报/模型时，只需新增“证据源”，不破坏裁决逻辑。

