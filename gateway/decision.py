"""访问判定引擎：纯函数，基于策略快照求值，结论可复现。"""

from __future__ import annotations

from datetime import UTC, datetime

from gateway.models import (
    Decision,
    DecisionResult,
    Purpose,
    ReasonCode,
    ResourceRecord,
    Subject,
)
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

    按维度逐一求值并**聚合全部不满足的依据**（而非只暴露第一个），
    维度顺序固定，原因以稳定原子码为前缀（见 ReasonCode）：

    1. 保留期：无规则或超期（超期仅 AUDIT_REVIEW 可审计引用，其余用途拒绝）；
    2. 授权：(角色, 用途, 敏感级别) 是否存在匹配授权；
    3. 视图：授权指向的视图是否已定义；
    4. 属性：主体是否具备视图要求的全部必要属性；
       授权缺失时，改按同 (角色, 用途) 下其他敏感级别授权的候选视图检查，
       使“无授权 + 缺属性”两类依据可同时暴露。
    """
    deny_reasons: list[str] = []
    info_reasons: list[str] = []
    audit_reference_only = False

    # 1. 保留期维度
    retention = policy.retention_days.get(resource.sensitivity)
    if retention is None:
        deny_reasons.append(f"{ReasonCode.NO_RETENTION_RULE.value}:{resource.sensitivity}")
    else:
        age_days = (_as_utc(now) - _as_utc(resource.created_at)).days
        if age_days > retention:
            if purpose is Purpose.AUDIT_REVIEW:
                info_reasons.append(
                    f"{ReasonCode.RETENTION_EXPIRED.value}:"
                    f"audit-reference-only(age={age_days}d)"
                )
                audit_reference_only = True
            else:
                deny_reasons.append(
                    f"{ReasonCode.RETENTION_EXPIRED.value}:{age_days}d>{retention}d"
                )

    # 2. 授权维度
    key = (subject.role, purpose.value, resource.sensitivity)
    view_name = policy.grants.get(key)
    if view_name is None:
        deny_reasons.append(
            f"{ReasonCode.NO_GRANT.value}:role={subject.role},"
            f"purpose={purpose.value},sensitivity={resource.sensitivity}"
        )

    # 3+4. 视图与属性维度
    if view_name is not None:
        view = policy.views.get(view_name)
        if view is None:
            deny_reasons.append(f"{ReasonCode.VIEW_UNDEFINED.value}:{view_name}")
        else:
            missing = sorted(
                policy.required_attributes.get(view_name, frozenset())
                - subject.attributes
            )
            if missing:
                deny_reasons.append(
                    f"{ReasonCode.MISSING_ATTRIBUTES.value}:{','.join(missing)}"
                )
    else:
        # 授权缺失时仍聚合属性维度：取同 (角色, 用途) 候选视图的必要属性
        candidate_views = {
            v for (r, p, _s), v in policy.grants.items()
            if r == subject.role and p == purpose.value
        }
        candidate_required: set[str] = set()
        for name in candidate_views:
            candidate_required |= set(
                policy.required_attributes.get(name, frozenset())
            )
        missing = sorted(candidate_required - set(subject.attributes))
        if missing:
            deny_reasons.append(
                f"{ReasonCode.MISSING_ATTRIBUTES.value}:{','.join(missing)}"
            )

    if deny_reasons:
        return DecisionResult(
            decision=Decision.DENY,
            reasons=tuple(deny_reasons),
            policy_version=policy.version,
        )

    assert view_name is not None  # 无拒绝依据时授权必然存在
    info_reasons.append(
        f"{ReasonCode.GRANT.value}:{key[0]}/{key[1]}/{key[2]}->view={view_name}"
    )
    return DecisionResult(
        decision=Decision.ALLOW,
        reasons=tuple(info_reasons),
        policy_version=policy.version,
        view=view_name,
        audit_reference_only=audit_reference_only,
    )
