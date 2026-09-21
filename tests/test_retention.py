"""保留期边界与策略版本可复现性。"""

from dataclasses import replace
from datetime import timedelta

import pytest

from gateway import AccessDeniedError, AccessGateway, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.models import ResourceRecord


def make_gw(store, sink=None):
    return AccessGateway(store, sink or InMemoryAuditSink(), b"test-key")


def test_retention_boundary(store, agent, now):
    gw = make_gw(store)
    at_limit = ResourceRecord("r90", "u1", "high", now - timedelta(days=90), {})
    over = ResourceRecord("r91", "u1", "high", now - timedelta(days=91), {})
    assert gw.access(agent, at_limit, Purpose.SERVICE, now).record_id == "r90"
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(agent, over, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("retention-expired")


def test_expired_record_audit_reference_only(store, record, now):
    expired = ResourceRecord("rX", "u1", "high", now - timedelta(days=200), record.fields)
    gw = make_gw(store)
    view = gw.access(Subject("au1", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    assert view.view == "audit_view"
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("a1", "analyst"), expired, Purpose.ANALYTICS, now)


def test_policy_update_does_not_rewrite_history(store, policy, record, agent, now):
    sink = InMemoryAuditSink()
    gw = make_gw(store, sink)
    gw.access(agent, record, Purpose.SERVICE, now)
    before = sink.records()[-1]
    assert before.decision == "allow" and before.policy_version == 1

    # 策略更新：收紧为拒绝
    v2 = replace(policy, version=2, grants={})
    store.update(v2)
    with pytest.raises(AccessDeniedError):
        gw.access(agent, record, Purpose.SERVICE, now)
    after = sink.records()[-1]
    assert after.decision == "deny" and after.policy_version == 2

    # 历史结论未被改写，且新旧结论可区分
    assert sink.records()[0].decision == "allow"
    assert sink.records()[0].policy_version != after.policy_version
