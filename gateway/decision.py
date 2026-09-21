"""访问判定引擎：纯函数，基于策略快照求值，结论可复现。"""

from __future__ import annotations

from datetime import UTC, datetime

from gateway.models import Decision, DecisionResult, Purpose, ResourceRecord, Subject
from gateway.policy import Policy


def evaluate(
    subject: Subject,
    resource: ResourceRecord,
    purpose: Purpose,
    policy: Policy,
    now: datetime,
) -> DecisionResult:
    """对一次访问请求求值，返回结论与依据。

    判定顺序固定，任一必要依据缺失即拒绝并给出可区分原因：
    1. 保留期检查（过期数据不可访问，仅可被 AUDIT_REVIEW 用途审计引用）；
    2. (角色, 用途, 敏感级别) 授权检查；
    3. 视图存在性与主体必要属性检查。
    """
    reasons: list[str] = []

    # 1. 保留期检查
    retention = policy.retention_days.get(resource.sensitivity)
    if retention is None:
        return DecisionResult(
            decision=Decision.DENY,
            reasons=(f"no-retention-rule:{resource.sensitivity}",),
            policy_version=policy.version,
        )
    def _as_utc(dt: datetime) -> datetime:
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)

    age_days = (_as_utc(now) - _as_utc(resource.created_at)).days
    if age_days > retention:
        if purpose is Purpose.AUDIT_REVIEW:
            reasons.append(f"retention-expired:audit-reference-only(age={age_days}d)")
        else:
            return DecisionResult(
                decision=Decision.DENY,
                reasons=(f"retention-expired:{age_days}d>{retention}d",),
                policy_version=policy.version,
            )

    # 2. 授权检查
    key = (subject.role, purpose.value, resource.sensitivity)
    view_name = policy.grants.get(key)
    if view_name is None:
        return DecisionResult(
            decision=Decision.DENY,
            reasons=(f"no-grant:role={subject.role},purpose={purpose.value},"
                     f"sensitivity={resource.sensitivity}",),
            policy_version=policy.version,
        )

    # 3. 视图与属性检查
    view = policy.views.get(view_name)
    if view is None:
        return DecisionResult(
            decision=Decision.DENY,
            reasons=(f"view-undefined:{view_name}",),
            policy_version=policy.version,
        )
    required = policy.required_attributes.get(view_name, frozenset())
    missing = sorted(required - subject.attributes)
    if missing:
        return DecisionResult(
            decision=Decision.DENY,
            reasons=(f"missing-attributes:{','.join(missing)}",),
            policy_version=policy.version,
        )

    reasons.append(f"grant:{key[0]}/{key[1]}/{key[2]}->view={view_name}")
    return DecisionResult(
        decision=Decision.ALLOW,
        reasons=tuple(reasons),
        policy_version=policy.version,
        view=view_name,
    )
