# Business Email Compromise（BEC）检测

BEC 的核心不是“技术恶意载荷”，而是**冒充与业务流程诱导**。因此该技能更依赖上下文与组织数据；在缺少上下文时，系统应倾向于 `suspicious` 并触发人工复核。

## 关键风险信号（通用）

- Reply-To 与 From 域名不一致（典型“回复劫持”）
- 付款/发票/银行转账等意图 + 强紧迫语气
- 与历史线程/联系人关系不匹配（当前系统未接入）
- 指令型动作：要求“回复/转账/更改收款信息”

## 当前实现覆盖

### 1) Reply-To mismatch（快速特征）

- 位置：`engine/router.py`
- 特征：`QuickFeatures.reply_to_mismatch`
- 用途：参与路由初筛与风险融合评分（`reply_to_mismatch`）

### 2) 语义意图与紧迫度（规则式）

工具：`semantic_extract()`（`tools_builtin/content_analyzer.py`）

- `intent` 可能为：
  - `invoice_payment`（发票/付款）
  - `credential_theft`（凭据）
  - `oauth_consent` 等协作意图
- `urgency`：0–3（基于关键词）

注意：当前 `scoring/fusion.py` 默认只对 `semantic_urgency` 与部分 intent（credential/oAuth）赋权；`invoice_payment` 尚未作为独立评分因子。

## 推荐的处置策略（缺上下文时）

- 若出现“付款/转账/更改收款信息”意图但技术证据不足：
  - verdict 建议倾向 `suspicious`
  - 推荐动作：通过内部渠道核验（电话/IM/财务系统），不要直接邮件回复

## 扩展建议（让 BEC 更可用）

1. 新增证据源（集成层提供）：
   - 组织通讯录/历史联系人
   - 付款请求的历史对比（新收款账号、首次供应商）
   - 线程上下文（In-Reply-To/References）
2. 将 `invoice_payment` 纳入风险融合：
   - 在 `scoring/fusion.py` 增加因子（如 `semantic_invoice_intent`）
   - 在 `configs/profiles/balanced.yaml` 配置权重并补测试

