# privacy-access-gateway

本地数据访问网关：对含个人敏感信息的记录进行**访问判定、字段脱敏与审计留痕**，
并沉淀**运行期决策日志**，使不同角色、用途与数据范围下的结论一致、可解释、
可复现且可观测。

## 架构

```
gateway/
  models.py       主体 / 资源 / 用途 / 判定结果 / 原子原因码等不可变数据模型
  policy.py       策略定义（Policy）与线程安全的版本化策略存储（PolicyStore）
  decision.py     纯函数判定引擎 evaluate()，多维度拒绝原因聚合
  masking.py      字段级脱敏、确定性令牌化与超期审计引用句柄
  audit.py        审计记录与线程安全的内存审计存储
  decision_log.py 运行期决策日志（结构化条目、内存/ logging 两种落点）
  service.py      AccessGateway 编排：取快照 → 判定 → 审计 → 日志 → 脱敏输出
main.py           FastAPI 演示服务（查询记录 / 查看审计 / 查看决策日志）
tests/            pytest 测试
```

## 判定模型

一次访问由四元组决定：**主体（角色 + 属性）× 用途 × 资源敏感级别 × 策略快照**。
判定按维度逐一求值，**所有不满足的维度一次性聚合列出**（而非只暴露第一个），
维度顺序固定：

| 顺序 | 维度 | 原子原因码 |
|---|---|---|
| 1 | 敏感级别存在保留期规则 / 记录未超保留期 | `no-retention-rule` / `retention-expired` |
| 2 | `(role, purpose, sensitivity)` 存在授权 | `no-grant` |
| 3 | 授权指向的视图已定义 | `view-undefined` |
| 4 | 主体具备视图要求的全部属性 | `missing-attributes` |

判定引擎是纯函数：相同输入（含策略快照与时间）必然得到相同结论，结论中携带
`policy_version` 与 `reasons`，可解释、可复现。

### 拒绝原因的分级与聚合

每条判定依据的格式为 **`<原子原因码>:<细节参数>`**，原因码是稳定、彼此可区分的
枚举值（`ReasonCode`），细节参数只含非敏感信息（角色名、用途、敏感级别、
缺失属性名、保留天数等），绝不含原始敏感值。

- 一次访问同时存在多个不满足维度时（如无匹配授权 **且** 缺少必要属性），
  拒绝依据一次性列出全部维度，调用方可一次改到位；
- 授权缺失时，属性维度按同 `(角色, 用途)` 下其他敏感级别授权的候选视图检查，
  使两类依据可同时暴露；
- `AccessDeniedError` 同时提供 `.reasons`（全部原子原因元组）与 `.reason`
  （分号连接的汇总字符串），错误归类方式与既有版本一致。

## 运行期决策日志

每一次访问判定（无论结局）恰好产生一条结构化决策日志，与审计留痕相互独立：
审计面向合规存档，决策日志面向运维排障。日志条目字段：

| 字段 | 含义 |
|---|---|
| `timestamp` | 判定时间 |
| `subject_id` / `role` | 主体标识与角色 |
| `resource_id` | 资源标识 |
| `purpose` | 访问用途 |
| `outcome` | 最终结局：`allow` / `deny` / `audit_failed` / `masking_failed` |
| `decision` | 判定结论本身：`allow` / `deny` |
| `reasons` | 逐条判定依据（原子原因码 + 细节） |
| `policy_version` | 判定所用策略版本 |

语义保证：

- **不含敏感值**：日志只含标识与判定依据，任何路径（含失败路径）都不会
  出现姓名、证件号、手机号等原始敏感值明文；
- **不影响结论**：日志写入是尽力而为的，日志后端失败绝不改变既有的
  放行/拒绝结论；
- **线程安全、恰好一条**：并发访问下每条判定恰好产生一条日志，不丢不重；
- 落点可选：`InMemoryDecisionLogSink`（本地断言用）或
  `LoggingDecisionLogSink`（单行 JSON 打入 stdlib logging，可用 caplog
  等日志捕获按关键字段断言），也可注入自定义 `DecisionLogSink`。

## 脱敏规则

每个权限视图（`ViewRule`）声明三类字段，输出集合与规则完全确定：

- `plain_fields`：明文输出；
- `tokenized_fields`：HMAC-SHA256 确定性令牌化（`tok_<hex>`），同密钥同值同令牌；
- `masked_fields`：掩码规则 `full`（`***`）/ `last4`（`***1234`）/ `first1`（`张***` 形式）。

未在视图中声明的字段**一律不输出**；越权字段不会出现在响应、错误信息或日志中。

## 保留期策略与超期审计引用

`retention_days` 按敏感级别配置保留天数。记录年龄 ≤ 保留期可正常访问；
超过保留期后：

- **普通用途一律拒绝**（`retention-expired:`），保留期边界结论与既有版本一致；
- **`audit_review` 用途仅可审计引用**：返回结果中不含任何个人字段——
  明文、掩码、令牌化均不返回（`fields` 为空），只给一个可复现的引用句柄
  `reference`（`ref_<hex>`，HMAC-SHA256 摘要）。

引用句柄规则：同一记录在同一策略版本下句柄稳定可复现、与访问者无关；
策略版本变化后新旧句柄可区分；不同记录句柄不同；句柄无法反推记录内容。

策略更新整体替换并递增 `version`，历史审计记录与决策日志中的结论和
`policy_version` 不会被改写，新旧结论可区分、可复现。

## 并发与失败语义

- `PolicyStore` 读写加锁，更新为原子整体替换；单次判定只取一次快照，
  不会出现半更新状态，也不会在一次判定中读到过期策略。
- 审计先于放行：审计写入失败抛出 `AuditError`，访问不被静默放行；
  该结局同样会沉淀一条 `audit_failed` 决策日志。
- 错误归类可区分：`AccessDeniedError`（拒绝）、`MaskingError`（脱敏失败）、
  `AuditError`（审计失败）、`PolicyError`（策略非法），均为 `GatewayError` 子类。
- 所有状态对象不可变，任何失败不污染既有策略、不残留部分状态。

## 兼容范围

- 既有判定结论（放行/拒绝边界、保留期边界、脱敏输出）完全不变；
- `AccessDeniedError.reason` 保持分号连接字符串形式，新增 `.reasons` 元组；
- `AccessGateway` 新增可选参数 `decision_log`，缺省使用内存实现，既有构造方式不受影响；
- `AccessView` 新增 `reference` 字段（默认 `None`），未超期记录不受影响。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest tests/ -q # 运行测试（越权 / 保留期边界 / 并发更新 / 异常链路
                        # / 决策日志 / 超期审计引用 / 拒绝原因聚合）
uv run uvicorn main:app --reload   # 启动演示服务
```

演示请求：

```bash
# 客服角色按业务用途访问（需属性 dept:cs）
curl 'http://127.0.0.1:8000/records/r1?subject_id=s1&role=agent&purpose=service&attrs=dept:cs'
# 缺少必要属性 → 403 missing-attributes:dept:cs
curl 'http://127.0.0.1:8000/records/r1?subject_id=s1&role=agent&purpose=service'
# 超保留期记录仅审计用途可引用：fields 为空，仅返回 reference 句柄
curl 'http://127.0.0.1:8000/records/r2?subject_id=s9&role=auditor&purpose=audit_review'
# 查看审计留痕（含判定依据，不含原始敏感值）
curl 'http://127.0.0.1:8000/audit'
# 查看运行期决策日志（每次判定一条，含 outcome 与判定依据）
curl 'http://127.0.0.1:8000/decisions'
```
