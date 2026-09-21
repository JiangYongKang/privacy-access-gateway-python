# 判定模型

每次访问判定由五类依据 **共同** 决定，缺少任一必要依据即拒绝。
结论结构见 `models.AccessDecision` / `DecisionEvidence`。

## 判定输入

| 输入 | 来源 | 说明 |
| --- | --- | --- |
| 主体角色 | `Subject.roles` | 角色集合，任一命中规则角色即角色维度通过 |
| 主体属性 | `Subject.attributes` | `(key, value)` 集合，须包含规则要求的 **全部** 属性 |
| 访问用途 | `AccessPurpose` | 枚举：`support` / `analytics` / `marketing` / `audit` / `data_export` |
| 资源敏感级别 | `DataRecord.field_levels` | 每个字段都必须显式声明；按规则 **视图可见字段** 的最高级别参与判定 |
| 保留期 | `RetentionRule` + `DataRecord.collected_on` | 见 [retention-policy.md](retention-policy.md) |

敏感级别有序关系（判定时比较上限）：

```
public(0) < internal(1) < personal(2) < sensitive(3)
```

## 规则语义（`AccessRule`）

一条规则同时要求：

1. `roles ∩ subject.roles ≠ ∅`；
2. `required_attributes ⊆ subject.attributes`；
3. `purpose ∈ allowed_purposes`；
4. 视图可见字段的最高敏感级别 `≤ max_sensitivity`；
5. 记录在保留期内。

规则集合为有序元组，存在任意一条规则全部满足即 `allow`。
**维度聚合**：无规则完整匹配时，对每个依据维度判断“是否存在任一规则满足它”，
未满足的维度即为可区分原因。这样在多规则策略中，缺角色与缺属性不会互相污染
（例如：客服角色用户缺少部门属性时，只报 `missing_required_attribute`，
不会因为风控规则不匹配而被附带 `role_not_authorized`）。
若四个维度均成立但依据分散在不同规则中，回退为 `no_applicable_rule`。

## 结论类型

| `Decision` | 含义 | 响应 |
| --- | --- | --- |
| `allow` | 全部依据满足 | 返回按视图脱敏后的字段 |
| `deny` | 依据缺失/不足/显式拒绝 | 抛 `AccessDeniedError`，已写审计 |
| `audit_only` | 超过保留期但策略允许审计引用 | 空字段响应 + 审计 ID（无明文） |

## 可区分原因码（`DecisionEvidence.reasons` / 错误 `reason`）

| 原因码 | 触发条件 |
| --- | --- |
| `role_not_authorized` | 没有任何规则授予该主体角色 |
| `missing_required_attribute` | 角色可匹配，但规则要求的属性主体不具备 |
| `purpose_not_permitted` | 用途不在任何匹配规则的允许集合内 |
| `sensitivity_exceeds_rule` | 视图可见字段最高敏感级别超过规则上限 |
| `undeclared_field_sensitivity` | 记录存在未声明敏感级别的字段（必要依据缺失） |
| `no_applicable_rule` | 维度均成立但无单一规则完整匹配；或策略无规则 |
| `policy_not_yet_effective` | 判定日期早于策略生效日 |
| `invalid_subject` / `invalid_record` | 主体/资源缺少必要 ID |
| `retention_expired_audit_only` | 超过保留期，仅可审计引用 |
| `retention_expired_denied` | 超过保留期且策略要求拒绝 |
| `future_collection_date` | 记录采集日期晚于判定日期（数据异常，保守拒绝） |

## 可解释性

每次判定的证据（`DecisionEvidence`）记录：

- `policy_version`、`matched_rule_id`；
- 五个布尔检查：`role_ok / attributes_ok / purpose_ok / sensitivity_ok / retention_ok`；
- `record_age_days`、`retention_days`；
- 排序去重后的原因码元组（确定性顺序）。

证据只含结构化判定信息，**不含任何字段值**。相同的
（策略版本, 主体, 记录, 用途, 判定日期）必然得到相同结论与证据。

## 判定流程

```
抓取策略不可变快照
  └─ 校验策略已生效、主体/记录 ID 完整
       └─ 校验全部字段已声明敏感级别
            └─ 保留期判定（过期优先：audit_only / deny / future）
                 └─ 规则匹配（角色 & 属性 & 用途 & 视图有效敏感级别）
                      ├─ 命中 → allow（后续：脱敏 → 审计 → 返回）
                      └─ 未命中 → deny（审计后拒绝，附维度原因）
```
