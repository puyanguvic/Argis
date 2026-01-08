# 项目代码结构

仓库结构（与 `README.md` 一致）：

```
.
├── agent/                 # 编排、裁决、解释与 CLI
├── schemas/               # 输入/证据/解释 schema（Pydantic）
├── tools/                 # 确定性证据源
├── scoring/               # 风险融合与硬规则
├── configs/               # 默认配置（YAML）
├── examples/              # 示例输入
├── tests/                 # 单元测试
├── apps/gradio_demo/      # 手工测试 UI
└── docs/                  # 本文档集
```

关键入口：

- CLI：`agent/cli.py`（`phish-agent`）
- 主编排：`agent/orchestrator.py`
- 路由：`agent/router.py`
- 裁决：`agent/policy.py` + `scoring/`

