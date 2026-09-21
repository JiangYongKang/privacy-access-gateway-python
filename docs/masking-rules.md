# 脱敏与令牌化规则

实现位于 `masking.py`，由 `FieldView` 声明每个角色视图的字段集合与输出模式。

## 字段视图（`FieldView`）

| 字段 | 含义 |
| --- | --- |
| `visible_fields` | 白名单：只有这些字段可能出现在响应中 |
| `masked_fields` | 其中以掩码输出的字段（须是 visible 的子集） |
| `tokenized_fields` | 其中以确定性令牌输出的字段（须是 visible 的子集） |

约束（发布策略与应用掩码时都会校验，违规分别报 `policy_error:invalid_view`
或 `masking_failed`）：

- 同一字段不能既掩码又令牌化（`ambiguous_field_mode`）；
- `masked_fields` / `tokenized_fields` 必须是 `visible_fields` 的子集。

## 输出模式

| mode | 规则 | 示例 |
| --- | --- | --- |
| `plain` | 白名单且未标注掩码/令牌（一般用于非敏感字段） | `Zhang` |
| `masked` | 长度 ≤ 4：全 `*`；长度 > 4：保留末 4 位，其余替换为 `*`，长度保持不变 | `123456` → `**3456`；`Zhang` → `*hang` |
| `tokenized` | `tok:` + HMAC-SHA256(盐, 值) 的前 16 位十六进制 | `tok:24f40f70c118d22c` |

### 令牌特性

- **确定性**：同盐同值永远得到同一令牌，可用于跨请求关联，又不暴露明文；
- **不可逆**：HMAC 单向派生，无法从令牌还原原文；
- **盐隔离**：盐通过构造参数注入（生产应通过安全渠道配置，不入库不进日志）；
- **不同值不同令牌**，同值不同盐不同令牌。

## 确定性保证

- 脱敏器只遍历 `visible_fields`，并按字段名 **排序输出**，
  相同输入永远得到字段顺序、模式、值都相同的输出；
- 视图引用了记录上不存在的字段时抛 `masking_failed:unknown_field`，
  绝不静默跳过；
- 记录字段缺少敏感级别声明时在判定阶段即被拒绝
  （`access_denied:undeclared_field_sensitivity`），不会进入脱敏。

## 防泄漏边界

1. 白名单之外的字段在脱敏器中根本不被读取，无法出现在响应；
2. 脱敏错误只携带字段名与原因码，不携带值；
3. 脱敏失败时网关尝试写审计（`detail=masking_failed:<reason>`，无值）后抛错；
   若审计也失败则以 `audit_failed` 为准，绝不返回数据；
4. 日志只记录 `字段名:模式`（如 `name:masked,phone:tokenized`），不记录值。

## 授权与脱敏的关系

授权规则中的 `max_sensitivity` 按 **该规则视图可见字段** 的最高敏感级别计算，
而非整条记录：客服视图只暴露 `name(personal)`，即使同一条记录还包含
`id_card(sensitive)`，客服仍可在 personal 上限内获得掩码姓名；
反过来，任何视图一旦把 `sensitive` 字段纳入可见集合，
personal 上限的规则就无法命中（`sensitivity_exceeds_rule`）。
