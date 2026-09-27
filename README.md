# privacy-access-gateway

本地数据访问网关：对含个人敏感信息的记录进行**访问判定、字段脱敏、审计留痕与
运行期决策日志**，使不同角色、用途与数据范围下的结论一致、可解释且可复现。

## 架构

```
gateway/
  models.py       主体 / 资源 / 用途 / 判定结果等不可变数据模型
  policy.py       策略定义（Policy）与线程安全的版本化策略存储（PolicyStore）
  decision.py     纯函数判定引擎 evaluate()（多维度拒绝原因聚合）
  masking.py      字段级脱敏与确定性令牌化
  reference.py    超期记录的仅审计引用句柄（HMAC 派生，可复现）
  audit.py        审计记录与线程安全的内存审计存储
  decision_log.py 运行期决策日志（结构化、线程安全、每次判定恰好一条、输出端故障隔离/兜底/死信补发）
  service.py      AccessGateway 编排：取快照 → 判定 → 审计 → 脱敏/引用 → 决策日志
main.py           FastAPI 演示服务（查询记录 / 查看审计）
tests/            pytest 测试
```

## 判定模型与拒绝原因聚合

一次访问由四元组决定：**主体（角色 + 属性）× 用途 × 资源敏感级别 × 策略快照**。
判定按固定维度顺序求值，**所有可独立求值的不满足维度一次性聚合列出**，
而非只暴露第一个，便于调用方一次改到位。每个维度用稳定、彼此可区分的
原子原因标识表达：

| 顺序 | 维度 | 原子原因前缀 |
|---|---|---|
| 1 | 敏感级别存在保留期规则 | `no-retention-rule:` |
| 2 | 记录未超保留期（超期仅 `audit_review` 可审计引用） | `retention-expired:` |
| 3 | `(role, purpose, sensitivity)` 存在授权 | `no-grant:` |
| 4 | 授权指向的视图已定义 | `view-undefined:` |
| 5 | 主体具备视图要求的必要属性 | `missing-attributes:` |

分级方式：维度 1–2 为**数据可留存性**，维度 3 为**授权**，维度 4–5 为
**视图与主体属性**。属性维度在视图名可确定时即可求值；授权缺失时退而检查同一
`(角色, 用途)` 下其他敏感级别授权所指向视图的必要属性，因此
`no-grant:` 与 `missing-attributes:` 可同时出现。多个缺失属性按字典序聚合在
同一条 `missing-attributes:a,b` 内。拒绝时 `AccessDeniedError.reason` 为全部
原子原因以 `;` 连接，顺序固定、可复现。

判定引擎是纯函数：相同输入（含策略快照与时间）必然得到相同结论，结论中携带
`policy_version` 与 `reasons`，可解释、可复现。

## 运行期决策日志

每一次访问判定（无论结局）都恰好发射**一条**结构化运行日志，logger 名为
`gateway.decision`，级别 INFO，消息为 `access_decision <json>`；JSON 负载
同时以 `dl_<字段>` 形式挂在 `LogRecord` 上，便于本地用日志捕获（如 pytest
`caplog`）按关键字段断言。

字段（均为可机读的判定依据，**绝不含任何原始敏感值**）：

| 字段 | 含义 |
|---|---|
| `log_id` | 本条日志全局唯一标识（`dl-<hex>`），用于故障兜底与去重 |
| `timestamp` | 判定时间（ISO 格式） |
| `subject_id` / `role` | 主体标识与角色 |
| `resource_id` | 资源标识 |
| `purpose` | 访问用途 |
| `decision` | **判定本身的结论**：`allow` / `deny`，所有结局都携带，与输出端故障无关 |
| `outcome` | 最终结局：`allow` / `deny` / `audit_error` / `masking_error` |
| `policy_version` | 判定所用策略版本 |
| `reasons` | 逐条原子原因（放行时为授权命中等依据） |
| `view` | 放行时使用的视图名（否则为 null） |
| `reference` | 超期仅审计引用时的句柄（否则为 null） |

`decision` 与 `outcome` 是两个不同维度：前者回答“**判定放不放行**”，后者回答
“**请求最终怎么收场**”。即使结局是审计或脱敏失败，也能直接机读底层判定：

| outcome | decision | 含义 |
|---|---|---|
| `allow` | `allow` | 正常放行并返回脱敏视图（或超期仅审计引用） |
| `deny` | `deny` | 判定拒绝，抛出 `AccessDeniedError` |
| `audit_error` | `allow` 或 `deny` | 审计写入失败；底层判定可能是放行也可能是拒绝，统一归类为 `AuditError` |
| `masking_error` | `allow` | 判定放行但字段脱敏失败，归类为 `MaskingError`，不返回任何字段 |

语义保证：

- **恰好一条**：放行、拒绝、审计写入失败、脱敏失败四条路径各发射且仅发射一条；
  每条带唯一 `log_id`，可辨认、可对账；
- **线程安全 / 不丢不重**：发射器内部加锁并按 `log_id` 去重，并发访问下每次判定
  恰好一条，失败重试也不会产生第二条；
- **不改变结论**：日志发射在判定之后，且 `emit()` 在任何情况下都不向调用方抛异常，
  日志故障绝不影响放行/拒绝结果与错误归类；
- **不泄漏**：日志只含标识与依据，姓名、证件号、手机号等原始敏感值一律不出现；
  输出端故障时只保留异常**类型名**用于计数，绝不记录异常文本（第三方输出端可能
  把请求数据拼进异常消息），错误信息中也不出现敏感原值。

### 日志输出端故障时的行为

`DecisionLogger` 由主输出端与兜底输出端组成（默认主端为标准 `logging`，
兜底为 stderr 单行 JSON）：

1. **主端失败**：自动转投兜底端，消息前缀 `access_decision_fallback`，
   请求对外行为完全不变；
2. **两端皆失败**：条目进入进程内**死信队列**，不抛异常、不阻塞请求，可随后调用
   `DecisionLogger.retry_dead_letters()` 补发（已投递的按 `log_id` 跳过，绝不重复）；
3. 主端可注入：`DecisionLogger(sink=..., fallback=...)`，再经
   `AccessGateway(..., decision_logger=...)` 接入；
4. `stats()` 返回 `delivered / primary_failures / fallback_delivered /
   dead_lettered / dead_pending` 计数（不含任何请求内容），`dead_letters()`
   返回待补发条目，便于本地核对不丢不重。

## 脱敏规则

每个权限视图（`ViewRule`）声明三类字段，输出集合与规则完全确定：

- `plain_fields`：明文输出；
- `tokenized_fields`：HMAC-SHA256 确定性令牌化（`tok_<hex>`），同密钥同值同令牌；
- `masked_fields`：掩码规则 `full`（`***`）/ `last4`（`***1234`）/ `first1`（`张***` 形式）。

未在视图中声明的字段**一律不输出**；越权字段不会出现在响应、错误信息或日志中。

## 保留期策略与超期仅审计引用

`retention_days` 按敏感级别配置保留天数。记录年龄 ≤ 保留期可正常访问；
超过保留期后：

- **普通用途一律拒绝**（`retention-expired:`），既有保留期边界结论不变；
- **仅 `audit_review` 用途可审计引用**：返回结果中**不含任何个人字段**
  （明文、掩码、令牌化均不输出，`fields` 为空），只携带一个可复现的
  **引用句柄** `reference`（`ref_<hex>`）。

句柄由 `(记录标识, 策略版本)` 经 HMAC-SHA256 派生：同一记录在同一策略版本下
稳定可复现；策略版本变化后新旧句柄可区分；句柄不含、也不可反推任何原始
敏感字段值。策略更新整体替换并递增 `version`，历史审计记录中的结论与
`policy_version` 不会被改写，新旧结论可区分、可复现。

## 并发与失败语义

- `PolicyStore` 读写加锁，更新为原子整体替换；单次判定只取一次快照，
  不会出现半更新状态，也不会在一次判定中读到过期策略。
- 审计先于放行：审计写入失败抛出 `AuditError`，访问不被静默放行；即使底层判定为
  拒绝，审计失败仍归类为 `AuditError`，日志的 `decision` 字段同时保留 `deny`。
- 错误归类可区分：`AccessDeniedError`（拒绝）、`MaskingError`（脱敏失败）、
  `AuditError`（审计失败）、`PolicyError`（策略非法），均为 `GatewayError` 子类；
  决策日志输出端故障**不改变**上述归类与对外返回（见“日志输出端故障时的行为”）。
- 所有状态对象不可变，任何失败不污染既有策略、不残留部分状态。

## 兼容范围

- 既有行为不变：保留期边界（年龄 ≤ 保留期放行）、未超期记录的脱敏输出、
  审计先于放行、错误归类方式、判定可复现性均保持原语义；
- 单一维度不满足时拒绝原因仍为原来的一条，不引入额外原因；
- 新增能力均为向后兼容扩展：`DecisionResult.audit_reference_only`、
  `AccessView.reference` 有默认值；决策日志为新增输出，不改变既有返回值与异常。
  日志负载新增 `log_id` 与 `decision` 字段，`outcome` 取值保持不变。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest tests/ -q # 运行测试（越权 / 保留期边界 / 并发更新 / 异常链路 /
                        # 决策日志 / 日志端故障隔离与兜底 / 超期仅审计引用 / 拒绝原因聚合）
uv run uvicorn main:app --reload   # 启动演示服务
```

演示请求：

```bash
# 客服角色按业务用途访问（需属性 dept:cs）
curl 'http://127.0.0.1:8000/records/r1?subject_id=s1&role=agent&purpose=service&attrs=dept:cs'
# 缺少必要属性 → 403 missing-attributes:dept:cs
curl 'http://127.0.0.1:8000/records/r1?subject_id=s1&role=agent&purpose=service'
# 超保留期记录仅审计用途可引用：fields 为空，仅返回可复现 reference 句柄
curl 'http://127.0.0.1:8000/records/r2?subject_id=s9&role=auditor&purpose=audit_review'
# 查看审计留痕（含判定依据，不含原始敏感值）
curl 'http://127.0.0.1:8000/audit'
```

本地捕获决策日志做断言（pytest）：

```python
def test_decision_log(caplog):
    with caplog.at_level("INFO", logger="gateway.decision"):
        ...  # 触发访问
    entry = json.loads(caplog.records[-1].getMessage().split(" ", 1)[1])
    assert entry["decision"] == "allow"  # 判定结论：allow / deny，各结局均携带
    assert entry["outcome"] == "allow" and entry["policy_version"] == 1
    assert entry["log_id"]  # 每条日志的唯一标识
```

本地验证日志输出端故障（注入一个必失败的主端，断言对外结论不被带偏、

兜底不丢不重、敏感值不泄漏）：

```python
from gateway import AccessGateway, DecisionLogger

class FailingLogSink:
    def write(self, entry):
        raise RuntimeError("boom")  # 异常文本不会进入任何日志或错误信息

dl = DecisionLogger(FailingLogSink())  # 主端失败 -> 自动转投 stderr 兜底端
gw = AccessGateway(store, audit_sink, token_key, decision_logger=dl)
view = gw.access(agent, record, Purpose.SERVICE)  # 仍正常返回脱敏视图，不外抛
assert dl.stats()["delivered"] == 1 and dl.stats()["dead_pending"] == 0
```

对应自动化用例见 `tests/test_decision_log_failures.py`，覆盖：

- 主端失败时的放行、拒绝、审计失败（底层 allow 与 deny 两种）、脱敏失败路径，
  断言对外返回与错误归类不被改变，且各结局的 `decision` 均可机读；
- 双端失败进死信队列、恢复后 `retry_dead_letters()` 补发不重复、同 `log_id`
  重放幂等；
- 故障异常文本（含注入的敏感值）不出现在兜底端、死信与计数信息中；
- 高并发 + 间歇性主端失败下，每条判定恰好一条日志（不丢、不重、线程安全）。
