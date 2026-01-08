# 如何新增 Skill

“Skill”在本项目中最终落地为：新的证据源（tools）+ 新的证据字段（schemas）+ 新的评分/规则（scoring/policy）+ 文档与测试。

## 步骤建议

1. 定义你要解决的攻击类型与可观测证据
2. 扩展 `EvidenceStore`
   - 在 `schemas/evidence_schema.py` 新增字段与结果模型
3. 实现证据源工具
   - 在 `tools_builtin/` 新增 `*_analyzer.py`
   - 保证输出可序列化（Pydantic model 或 dict）
4. 将工具接入编排器与路由
   - 在 `engine/orchestrator.py` 的 `_build_tool_map()` 增加工具
   - 在 `engine/router.py` 的 profile tools 列表里配置（建议通过 `configs/profiles/balanced.yaml`）
5. 更新评分/硬规则
   - 在 `scoring/fusion.py` 增加 factor，并在 `configs/profiles/balanced.yaml` 配置权重
   - 或在 `scoring/rules.py` 增加 hard rule code
6. 更新报告/解释（如需要）
   - `engine/report.py` 增加证据条目（EvidenceLine）
7. 补测试与文档
   - `tests/` 增加回归
   - `docs/skills/<your_skill>.md` 记录信号、证据字段与限制

## 注意事项

- 优先把外部依赖做成“可选证据源”，避免让裁决直接依赖上游可用性
- 对在线工具启用 sandbox、超时与配额，失败应写入 `evidence.degradations`

