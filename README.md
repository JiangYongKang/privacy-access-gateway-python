# privacy-access-gateway

本地数据访问网关：对含个人敏感信息的记录进行**访问判定、字段脱敏与审计留痕**，
使不同角色、用途与数据范围下的结论一致、可解释且可复现。

## 架构

```
gateway/
  models.py    主体 / 资源 / 用途 / 判定结果等不可变数据模型
  policy.py    策略定义（Policy）与线程安全的版本化策略存储（PolicyStore）
  decision.py  纯函数判定引擎 evaluate()
  masking.py   字段级脱敏与确定性令牌化
  audit.py     审计记录与线程安全的内存审计存储
  service.py   AccessGateway 编排：取快照 → 判定 → 审计 → 脱敏输出
main.py        FastAPI 演示服务（查询记录 / 查看审计）
tests/         pytest 测试
```

## 判定模型

一次访问由四元组决定：**主体（角色 + 属性）× 用途 × 资源敏感级别 × 策略快照**。
判定按固定顺序求值，任一必要依据缺失即拒绝，且原因可区分：

| 顺序 | 检查 | 拒绝原因前缀 |
|---|---|---|
| 1 | 敏感级别存在保留期规则 | `no-retention-rule:` |
| 2 | 记录未超保留期（超期仅 `audit_review` 可审计引用） | `retention-expired:` |
| 3 | `(role, purpose, sensitivity)` 存在授权 | `no-grant:` |
| 4 | 授权指向的视图已定义 | `view-undefined:` |
| 5 | 主体具备视图要求的全部属性 | `missing-attributes:` |

判定引擎是纯函数：相同输入（含策略快照与时间）必然得到相同结论，结论中携带
`policy_version` 与 `reasons`，可解释、可复现。

## 脱敏规则

每个权限视图（`ViewRule`）声明三类字段，输出集合与规则完全确定：

- `plain_fields`：明文输出；
- `tokenized_fields`：HMAC-SHA256 确定性令牌化（`tok_<hex>`），同密钥同值同令牌；
- `masked_fields`：掩码规则 `full`（`***`）/ `last4`（`***1234`）/ `first1`（`张***` 形式）。

未在视图中声明的字段**一律不输出**；越权字段不会出现在响应、错误信息或日志中。

## 保留期策略

`retention_days` 按敏感级别配置保留天数。记录年龄 ≤ 保留期可正常访问；
超过保留期后：普通用途一律拒绝（`retention-expired:`），仅 `audit_review`
用途可按审计视图引用。策略更新整体替换并递增 `version`，历史审计记录中的
结论与 `policy_version` 不会被改写，新旧结论可区分、可复现。

## 并发与失败语义

- `PolicyStore` 读写加锁，更新为原子整体替换；单次判定只取一次快照，
  不会出现半更新状态，也不会在一次判定中读到过期策略。
- 审计先于放行：审计写入失败抛出 `AuditError`，访问不被静默放行。
- 错误归类可区分：`AccessDeniedError`（拒绝）、`MaskingError`（脱敏失败）、
  `AuditError`（审计失败）、`PolicyError`（策略非法），均为 `GatewayError` 子类。
- 所有状态对象不可变，任何失败不污染既有策略、不残留部分状态。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest tests/ -q # 运行测试（越权 / 保留期边界 / 并发更新 / 异常链路）
uv run uvicorn main:app --reload   # 启动演示服务
```

演示请求：

```bash
# 客服角色按业务用途访问（需属性 dept:cs）
curl 'http://127.0.0.1:8000/records/r1?subject_id=s1&role=agent&purpose=service&attrs=dept:cs'
# 缺少必要属性 → 403 missing-attributes:dept:cs
curl 'http://127.0.0.1:8000/records/r1?subject_id=s1&role=agent&purpose=service'
# 超保留期记录仅审计用途可引用
curl 'http://127.0.0.1:8000/records/r2?subject_id=s9&role=auditor&purpose=audit_review'
# 查看审计留痕（含判定依据，不含原始敏感值）
curl 'http://127.0.0.1:8000/audit'
```
