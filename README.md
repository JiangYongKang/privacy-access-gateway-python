# Privacy Access Gateway（本地数据访问网关）

对含个人敏感信息的记录进行 **访问判定、字段级脱敏/令牌化、审计留痕** 的本地网关。
目标：不同角色、用途、数据范围下的结论 **一致、可解释、可复现**。

## 能力概览

| 能力 | 实现位置 | 说明 |
| --- | --- | --- |
| 多维访问判定 | `evaluator.py` | 主体角色 **且** 属性、资源敏感级别、访问用途、保留期共同决定结论；任一必要依据缺失即拒绝并给出可区分原因码 |
| 字段脱敏/令牌化 | `masking.py` | 视图定义可见字段集合与掩码/令牌规则；视图外字段物理上不进入输出；HMAC 确定性令牌 |
| 保留期与合规 | `retention.py` / `evaluator.py` | 超期按策略拒绝或仅可审计引用；策略带版本，历史结论按版本复现、不被改写 |
| 审计留痕 | `audit.py` / `gateway.py` | 每次判定记录主体/资源/用途/结论/依据；审计写入失败绝不静默放行 |
| 并发一致 | `policy_store.py` | 策略为不可变快照，发布整包原子替换 + 版本严格递增；判定抓取快照，无半更新、无脏读 |
| 错误分类 | `errors.py` | `access_denied` / `masking_failed` / `audit_failed` / `policy_error` 四类可区分错误 |

## 目录结构

```
src/privacy_gateway/
  models.py         # 领域模型（不可变 dataclass）
  errors.py         # 可区分错误类型
  evaluator.py      # 判定引擎
  masking.py        # 脱敏与确定性令牌化
  retention.py      # 保留期计算
  policy_store.py   # 版本化、原子发布的策略存储
  audit.py          # 审计通道与审计条目构造
  gateway.py        # 编排：判定 -> 脱敏 -> 审计
  app.py            # FastAPI 适配层
tests/              # pytest 测试（38 个，覆盖越权/边界/并发/异常链路）
docs/
  decision-model.md # 判定模型
  masking-rules.md  # 脱敏规则
  retention-policy.md # 保留期策略与历史可复现
```

## 快速开始

需要 Python ≥ 3.14 与 [uv](https://docs.astral.sh/uv/)。

```bash
uv sync                       # 安装依赖（含 dev 的 pytest）
uv run pytest                 # 运行全部测试
uv run uvicorn main:app --reload   # 启动本地 HTTP 服务
```

健康检查：

```bash
curl -s http://127.0.0.1:8000/healthz
```

### 一次完整调用（发布策略 → 访问）

```bash
# 1) 发布 v1 策略：客服角色 + cs 部门属性 + support 用途，可见 name（掩码）
curl -s -X POST http://127.0.0.1:8000/v1/policies -H 'content-type: application/json' -d '{
  "version": 1,
  "effective_from": "2026-01-01",
  "rules": [{
    "rule_id": "r-support",
    "roles": ["support"],
    "allowed_purposes": ["support"],
    "max_sensitivity": "personal",
    "required_attributes": [["dept", "cs"]],
    "field_view": "support_view"
  }],
  "views": {
    "support_view": {"visible_fields": ["name"], "masked_fields": ["name"]}
  },
  "retention": {"customer": {"retention_days": 30, "expired_action": "audit_only"}}
}'

# 2) 访问（注意 id_card 虽在记录中，但不在视图里，绝不返回）
curl -s -X POST http://127.0.0.1:8000/v1/access -H 'content-type: application/json' -d '{
  "subject": {"subject_id": "s1", "roles": ["support"], "attributes": [["dept", "cs"]]},
  "record": {
    "record_id": "rec1", "resource_type": "customer", "collected_on": "2026-09-10",
    "fields": {"name": "Zhang", "id_card": "110101199001011234"},
    "field_levels": {"name": "personal", "id_card": "sensitive"}
  },
  "purpose": "support",
  "today": "2026-09-21"
}'
```

返回（只含掩码后的 `name`，并附判定依据 `evidence`）：

```json
{
  "decision": "allow",
  "audit_id": "...",
  "view": "support_view",
  "evidence": {
    "policy_version": 1,
    "matched_rule_id": "r-support",
    "checks": {"role": true, "attributes": true, "purpose": true,
               "sensitivity": true, "retention": true},
    "record_age_days": 11,
    "retention_days": 30,
    "reasons": []
  },
  "fields": [{"name": "name", "mode": "masked", "value": "*hang"}]
}
```

拒绝时返回统一错误信封（只有错误码与原因码，**不含任何敏感值**）：

```json
{"error": {"code": "access_denied", "reason": "role_not_authorized"}}
```

## 本地验证方法

```bash
uv run pytest -v                      # 全量测试
uv run pytest tests/test_concurrency.py -v   # 只看并发：原子发布/无半更新
uv run pytest tests/test_retention.py -v     # 只看保留期边界与历史复现
uv run pytest tests/test_failure_paths.py -v # 只看异常链路
python -m compileall -q src main.py   # 纯编译检查
```

测试矩阵：

- 越权访问：无角色、缺属性、用途不符、敏感级别超限、字段未声明级别；
- 保留期边界：第 N 天可访问 / 第 N+1 天过期 / `audit_only` 与 `deny` 两种过期动作；
- 策略并发更新：7 读线程 × 50 次发布，结论始终来自某个完整策略版本；
- 异常链路：审计通道故障时允许与拒绝路径都不静默；脱敏失败可区分且留痕；
- 无泄漏：响应、错误文本、日志、审计条目均断言不含原始身份证号/手机号。

## 安全边界（设计约束）

1. 错误、日志、审计只携带 **ID、用途、结论、结构化原因码、字段输出模式**，
   绝不携带原始字段值；
2. 字段可见性由 `FieldView` 白名单决定，脱敏器只遍历白名单字段，
   因此越权字段无法通过任何错误分支进入响应；
3. 审计写失败优先级最高——即使判定允许，审计失败也返回 `audit_failed`；
4. 策略不可变 + 版本号，历史判定的 `policy_version` 与证据永久可追溯。
