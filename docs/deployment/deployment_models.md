# 部署模型：Local / Cloud / Hybrid

本项目可以以多种形态部署，核心建议是把“接入层”与“检测核心”解耦。

## 1) Local（本地/离线）

适用于：

- 安全团队分析、研究与离线回放
- 不允许出域/不允许联网的环境

方式：

- CLI：`phish-agent detect ...`
- Gradio：`python apps/demo/gradio_app.py`

## 2) Cloud（服务化）

适用于：

- 作为邮件网关/安全平台的后端检测服务

建议架构：

- 接入层：解析邮件、脱敏、补齐组织上下文
- 检测服务：只接收 `EmailInput`，输出 JSON
- 事件层：将结果写入 SIEM/SOAR

## 3) Hybrid（混合）

适用于：

- 检测核心离线运行，但允许部分“在线证据源”在隔离环境中运行

关键点：

- 在线工具需受 sandbox/egress allowlist/超时配额约束
- 在线证据只作为 `EvidenceStore` 的额外字段，不直接裁决

