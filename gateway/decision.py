"""访问判定引擎：纯函数，基于策略快照求值，结论可复现。"""

from __future__ import annotations

from datetime import UTC, datetime

from gateway.models import Decision, DecisionResult, Purpose, ResourceRecord, Subject
from gateway.policy import Policy


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def evaluate(
    subject: Subject,
    resource: ResourceRecord,
    purpose: Purpose,
    policy: Policy,
    now: datetime,
) -> DecisionResult:
    """对一次访问请求求值，返回结论与依据。

    按固定维度顺序求值，所有可独立求值的不满足维度一次性聚合列出，
    每个维度用稳定、彼此可区分的原子原因标识表达：
    1. 保留期规则存在性（no-retention-rule:）；
    2. 保留期边界（retention-expired:；超期仅 AUDIT_REVIEW 可审计引用）；
    3. (角色, 用途, 敏感级别) 授权（no-grant:）；
    4. 授权指向的视图已定义（view-undefined:）；
    5. 主体具备视图要求的必要属性（missing-attributes:）。

    属性维度在视图名可确定时即可求值：授权缺失时，退而求其次检查同一
    (角色, 用途) 下其他敏感级别授权所指向视图的必要属性，便于调用方一次改到位。
    """
    deny_reasons: list[str] = []  # 不满足维度的原子原因（任一存在即拒绝）
    allow_basis: list[str] = []   # 放行依据（审计引用说明、授权命中）
    audit_reference_only = False

    # 维度 1+2：保留期规则与边界
    retention = policy.retention_days.get(resource.sensitivity)
    if retention is None:
        deny_reasons.append(f"no-retention-rule:{resource.sensitivity}")
    else:
        age_days = (_as_utc(now) - _as_utc(resource.created_at)).days
        if age_days > retention:
            if purpose is Purpose.AUDIT_REVIEW:
                audit_reference_only = True
                allow_basis.append(
                    f"retention-expired:audit-reference-only(age={age_days}d)"
                )
            else:
                deny_reasons.append(f"retention-expired:{age_days}d>{retention}d")

    # 维度 3：授权检查
    key = (subject.role, purpose.value, resource.sensitivity)
    view_name = policy.grants.get(key)
    if view_name is None:
        deny_reasons.append(
            f"no-grant:role={subject.role},purpose={purpose.value},"
            f"sensitivity={resource.sensitivity}"
        )
        # 属性维度仍可求值：同一 (角色, 用途) 下其他敏感级别授权指向的候选视图
        candidates = {
            v for (r, p, _), v in policy.grants.items()
            if r == subject.role and p == purpose.value
        }
        required = frozenset().union(
            *(policy.required_attributes.get(v, frozenset()) for v in candidates)
        ) if candidates else frozenset()
        missing = sorted(required - subject.attributes)
        if missing:
            deny_reasons.append(f"missing-attributes:{','.join(missing)}")
    else:
        # 维度 4：视图存在性
        if view_name not in policy.views:
            deny_reasons.append(f"view-undefined:{view_name}")
        # 维度 5：必要属性（视图名已知即可求值，与视图是否已定义相互独立）
        required = policy.required_attributes.get(view_name, frozenset())
        missing = sorted(required - subject.attributes)
        if missing:
            deny_reasons.append(f"missing-attributes:{','.join(missing)}")

    if deny_reasons:
        return DecisionResult(
            decision=Decision.DENY,
            reasons=tuple(deny_reasons),
            policy_version=policy.version,
        )

    allow_basis.append(f"grant:{key[0]}/{key[1]}/{key[2]}->view={view_name}")
    return DecisionResult(
        decision=Decision.ALLOW,
        reasons=tuple(allow_basis),
        policy_version=policy.version,
        view=view_name,
        audit_reference_only=audit_reference_only,
    )
