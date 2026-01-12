---
layout: default
---

# 项目代码结构

仓库结构（与 `README.md` 一致）：

```
.
├── protocol/              # UI <-> Engine 稳定契约
├── engine/                # 核心引擎（session/task/turn + 检测流水线）
├── tools_builtin/         # 确定性证据源
├── providers/             # 模型适配层
├── connectors/            # 外部系统接入
├── apps/                  # CLI/Gradio 等入口
├── schemas/               # 输入/证据/解释 schema（Pydantic）
├── scoring/               # 风险融合与硬规则
├── configs/               # Profiles / providers / connectors
├── examples/              # 示例输入
├── tests/                 # 单元测试
└── docs/                  # 本文档集
```

关键入口：

- CLI：`apps/cli/main.py`（`phish-agent`）
- Engine loop：`engine/argis.py`
- 主编排：`engine/orchestrator.py`
- 路由：`engine/router.py`
- 裁决：`engine/policy.py` + `scoring/`
