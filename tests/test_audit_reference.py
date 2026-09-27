"""超期数据仅可审计引用：字段集合为空、句柄可复现、跨版本可区分。"""

from dataclasses import replace
from datetime import timedelta

import pytest

from gateway import AccessDeniedError, AccessGateway, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.models import ResourceRecord

SECRETS = ("张三", "13800001234", "330102199001011234")


@pytest.fixture()
def expired(record, now) -> ResourceRecord:
    return ResourceRecord("rX", "u1", "high", now - timedelta(days=200), record.fields)


def make_gw(store):
    return AccessGateway(store, InMemoryAuditSink(), b"test-key")


def test_expired_audit_reference_returns_no_fields(store, expired, now):
    gw = make_gw(store)
    view = gw.access(Subject("au1", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    assert view.fields == {}  # 明文/掩码/令牌化字段一律不返回
    assert view.reference is not None and view.reference.startswith("ref_")
    # 响应整体不含任何原始敏感值
    for secret in SECRETS:
        assert secret not in str(view)


def test_audit_reference_handle_is_reproducible(store, expired, now):
    gw = make_gw(store)
    v1 = gw.access(Subject("au1", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    v2 = gw.access(Subject("au2", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    # 同一记录同一策略版本：句柄稳定可复现，与访问者无关
    assert v1.reference == v2.reference


def test_audit_reference_handle_distinguishes_policy_versions(store, policy, expired, now):
    gw = make_gw(store)
    before = gw.access(Subject("au1", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    store.update(replace(policy, version=2))
    after = gw.access(Subject("au1", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    assert before.reference != after.reference  # 新旧版本句柄可区分
    assert before.reference.startswith("ref_") and after.reference.startswith("ref_")


def test_audit_reference_handle_distinguishes_records(store, expired, record, now):
    other = ResourceRecord("rY", "u2", "high", expired.created_at, record.fields)
    gw = make_gw(store)
    rx = gw.access(Subject("au1", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    ry = gw.access(Subject("au1", "auditor"), other, Purpose.AUDIT_REVIEW, now)
    assert rx.reference != ry.reference


def test_expired_record_still_denied_for_normal_purposes(store, expired, agent, now):
    gw = make_gw(store)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(agent, expired, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("retention-expired")
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("a1", "analyst"), expired, Purpose.ANALYTICS, now)


def test_fresh_record_unaffected_by_reference_logic(store, record, agent, now):
    gw = make_gw(store)
    view = gw.access(agent, record, Purpose.SERVICE, now)
    assert view.reference is None  # 未超期记录走正常脱敏视图
    assert view.fields["phone"] == "***1234"
