# 保留期策略与历史结论可复现

实现位于 `retention.py`（计算）与 `evaluator.py`（处置）。

## 规则定义（`RetentionRule`）

按资源类型配置：

| 字段 | 含义 |
| --- | --- |
| `resource_type` | 资源类型（与 `DataRecord.resource_type` 对应） |
| `retention_days` | 保留天数，非负 |
| `expired_action` | 过期动作：`audit_only`（默认，仅可审计引用）或 `deny`（不可访问） |

未配置保留规则的资源类型不做保留期限制（视为始终可访问，
由其余依据继续判定）。

## 边界定义（确定性）

```
record_age_days = 判定日期 - DataRecord.collected_on   （整天）

age_days < 0                      → deny  (future_collection_date)
0 ≤ age_days ≤ retention_days     → allow（保留期内，最后一天仍可访问）
age_days > retention_days         → expired_action（audit_only / deny）
```

边界示例（`retention_days = 30`，采集日 `2026-09-01`）：

| 判定日期 | 年龄 | 结论 |
| --- | --- | --- |
| 2026-10-01 | 30 | `allow`（恰好第 30 天，仍在保留期内） |
| 2026-10-02 | 31 | `audit_only` / `deny`（刚过期） |

## 过期后的两种处置

- `audit_only`：网关返回 `GatewayResponse(decision=audit_only, fields=(), audit_id=...)`。
  调用方只能拿到审计引用，拿不到任何明文字段；
- `deny`：网关在写审计后抛 `AccessDeniedError(reason=retention_expired_denied)`。

保留期判定 **优先于角色判定**：无论角色权限多高，过期数据都不可读明文。

## 策略版本与历史可复现

- `Policy` 是不可变快照（frozen dataclass），带 `version` 与 `effective_from`；
- `PolicyStore.publish()` **先完整校验、再整包原子替换引用**：
  - 版本必须严格递增，否则 `policy_error:version_conflict`，现状不变；
  - 结构非法（未知视图、空角色、负保留期等）拒绝发布，现状不变；
  - 因此并发的访问判定只会看到“旧完整版”或“新完整版”，不存在半更新；
- 每次判定抓取一次快照并在证据中记录 `policy_version`；
- 策略调整 **不会改写既有判定**：已写入的审计条目永久保留当时的
  `policy_version`、`retention_days`、结论与原因码。用同一旧策略版本与
  相同输入重放，得到相同结论（见 `tests/test_retention.py` 中的
  `test_policy_change_does_not_rewrite_historical_decisions`）。

## 审计留痕（每次判定，三种结论都记录）

`AuditEntry` 字段：

```
audit_id, timestamp_iso, subject_id, record_id, resource_type,
purpose, decision(allow/deny/audit_only), policy_version,
evidence(结构化依据), detail(仅原因码或 字段名:模式 清单)
```

- 审计写入由单一锁串行化，顺序与调用顺序一致；
- 审计通道故障抛 `audit_failed`，**允许与拒绝路径都不静默**；
- 审计内容、日志、错误文本均不含原始敏感值。

## 并发模型

```
判定线程 A ─┐
判定线程 B ─┼─► PolicyStore.snapshot() ─► 拿到不可变 Policy 引用 ─► 全程使用该引用
判定线程 C ─┘                                  ▲
管理线程 ──► publish(v+1)：校验通过后整包替换 ──┘（已持有的旧引用不受影响）
```

同资源/同策略并发访问，因判定纯函数化（输入相同 → 输出相同）且策略快照
不可变，结论必然一致；发布与判定并发时也不会读到过期半状态。
