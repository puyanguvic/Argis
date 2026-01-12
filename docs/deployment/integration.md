---
layout: default
---

# 集成：SIEM / Email Gateway

本页描述与邮件网关、SIEM/SOAR 的集成模式与字段建议。

## 1) 典型集成流程

1. 邮件网关/平台捕获邮件事件（含 Message-ID、收件人等元数据）
2. 接入层解析邮件并生成 `EmailInput`
3. 调用检测核心（本项目）得到 JSON 输出
4. 根据 `recommended_action` 执行动作：
   - `allow`：放行
   - `warn`：提示用户 + 进入复核队列
   - `quarantine`：隔离/阻断
5. 将事件写入 SIEM 并关联工单

## 2) 字段建议

最小集合：

- `verdict`, `risk_score`, `recommended_action`, `top_signals`, `trace_id`, `profile`

增强集合（由接入层提供）：

- `message_id`, `thread_id`, `tenant_id`
- `sender`, `sender_domain`, `reply_to`, `recipient`
- `urls`（原始与规范化）、`attachments`（sha256/mime/size）
- `delivery_action`（网关动作）与最终处置结果

## 3) 安全建议

- 在工单/告警系统中避免直接展示可点击 URL（或默认禁用）
- 对 `suspicious` 与 BEC 相关 intent 设置更严格的人工审批流程

