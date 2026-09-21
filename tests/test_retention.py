"""保留期边界、过期动作、历史结论可复现测试。"""

from __future__ import annotations

from datetime import date

import pytest

from privacy_gateway.errors import AccessDeniedError
from privacy_gateway.models import AccessPurpose, Decision
from tests.factories import build_gateway, customer_record, support_subject

# 保留期 30 天，采集于 2026-09-01
COLLECTED = date(2026, 9, 1)


def test_last_day_of_retention_is_still_accessible_boundary():
    gw, _, _ = build_gateway()
    # age == retention_days (恰好第30天) 仍允许
    resp = gw.access(support_subject(), customer_record(collected_on=COLLECTED),
                     AccessPurpose.SUPPORT, today=date(2026, 10, 1))
    assert resp.decision.decision is Decision.ALLOW
    assert resp.decision.evidence.record_age_days == 30


def test_day_after_retention_is_audit_only():
    gw, _, sink = build_gateway()
    resp = gw.access(support_subject(), customer_record(collected_on=COLLECTED),
                     AccessPurpose.SUPPORT, today=date(2026, 10, 2))
    assert resp.decision.decision is Decision.AUDIT_ONLY
    assert resp.fields == ()           # 无明文
    assert resp.audit_id               # 但有审计引用
    assert "retention_expired_audit_only" in resp.decision.evidence.reasons
    entry = sink.entries()[-1]
    assert entry.decision == "audit_only"


def test_expired_deny_policy_raises_access_denied():
    from tests.factories import full_policy
    gw, store, _ = build_gateway()
    store.publish(full_policy(retention_days=30, version=2))  # 同动作不变
    # 构造 DENY 过期动作的新版本
    from privacy_gateway.models import Policy, RetentionRule
    old = store.current()
    deny_policy = Policy(
        version=3, effective_from=old.effective_from,
        rules=old.rules, views=old.views,
        retention={"customer": RetentionRule("customer", 30, Decision.DENY)},
    )
    store.publish(deny_policy)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(support_subject(), customer_record(collected_on=COLLECTED),
                  AccessPurpose.SUPPORT, today=date(2026, 10, 2))
    assert "retention_expired_denied" in ei.value.reason


def test_future_collection_date_is_denied():
    gw, _, _ = build_gateway()
    future_rec = customer_record(collected_on=date(2027, 1, 1))
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(support_subject(), future_rec, AccessPurpose.SUPPORT, today=date(2026, 9, 21))
    assert "future_collection_date" in ei.value.reason


def test_policy_change_does_not_rewrite_historical_decisions():
    """策略更新后，用旧策略版本仍可复现历史结论。"""
    from tests.factories import full_policy

    gw, store, sink = build_gateway()
    record = customer_record(collected_on=COLLECTED)
    # 旧策略（v1，retention=30，audit_only）：2026-10-02 为 audit_only
    resp_v1 = gw.access(support_subject(), record, AccessPurpose.SUPPORT,
                        today=date(2026, 10, 2))
    assert resp_v1.decision.decision is Decision.AUDIT_ONLY
    assert resp_v1.decision.evidence.policy_version == 1

    # 策略更新：保留期缩短为 10 天
    store.publish(full_policy(retention_days=10, version=2))
    resp_v2 = gw.access(support_subject(), record, AccessPurpose.SUPPORT,
                        today=date(2026, 10, 2))
    assert resp_v2.decision.evidence.policy_version == 2
    assert resp_v2.decision.evidence.retention_days == 10

    # 已写入的历史审计条目仍记录 v1 的依据，未被改写
    v1_entries = [e for e in sink.entries() if e.policy_version == 1]
    assert v1_entries and all(e.evidence.retention_days == 30 for e in v1_entries)
