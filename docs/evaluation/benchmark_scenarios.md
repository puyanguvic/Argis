---
layout: default
---

# 测试场景（Benchmark Scenarios）

本页给出一组建议的基准场景，用于回归测试与权重/规则调参。

## 1) 典型钓鱼（凭据诱导）

- DMARC fail + URL 包含 `login/verify` 关键词
- 预期：`phishing`（或命中硬规则）+ 高分

## 2) 短链/可疑 TLD

- URL 使用短链域（`bit.ly` 等）或可疑 TLD（`.zip/.click/...`）
- 预期：`suspicious` 或 `phishing`（视组合信号与阈值）

## 3) Lookalike 域名 + 凭据意图

- 域名与品牌距离极小（如 `micros0ft`）+ credential intent
- 预期：高分；若同时 SPF fail，可能命中硬规则

## 4) 协作/OAuth 诱导（低噪音）

- `semantic.intent` 为 `oauth_consent` 等 + 品牌实体命中 + 外部发件人
- 预期：FAST → STANDARD 上下文升级（`degradations` 标记），并补齐 URL 证据

## 5) 恶意附件投递

- `semantic.intent == "malware_delivery"` + `.exe/.js/.ps1` 附件
- 预期：命中 `malware_intent_executable_attachment`（硬规则）或高分

## 6) 正常邮件（对照组）

- 内部 allowlist 域名、无 URL、无认证失败、无强意图
- 预期：`benign` + 低分

## 落地建议

- 将场景转成 `EmailInput` JSON 样本放入 `examples/` 或直接写成 `tests/` 用例
- 对每个场景记录预期：`verdict`、`risk_score` 区间、`top_signals` 关键项

