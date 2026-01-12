---
layout: default
---

# 调试与 Trace

本项目提供“录制与回放”机制，适合做可复现调试与回归对比。

## 1) 快速调试：CLI + JSON 输入

```bash
phish-agent detect --input examples/email_sample.json
```

## 2) 录制执行轨迹（JSONL）

```bash
phish-agent detect --input examples/email_sample.json --record run.jsonl
```

你可以查看 `run.jsonl` 中每个 `node_name` 的输出，定位是哪一步产生了某条证据。

## 3) 回放（不运行工具）

```bash
phish-agent replay --record run.jsonl
```

回放会：

- 合并 JSONL 中的工具输出为 `EvidenceStore`
- 使用当前配置重新计算 verdict/score（`engine/player.py`）

适用于：

- 对比不同配置/规则版本的裁决差异
- 在无外部依赖的情况下复现 bug

## 4) 单元测试

```bash
pytest
```

建议新增或修改权重/规则时同步更新测试用例，避免回归。

