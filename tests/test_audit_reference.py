"""超期数据仅可审计引用：字段集合为空，句柄可复现、可按策略版本区分。"""

from dataclasses import replace
from datetime import timedelta

import pytest

from gateway import AccessDeniedError, AccessGateway, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.models import ResourceRecord

SECRETS = ("张三", "13800001234", "330102199001011234")


def make_gw(store):
    return AccessGateway(store, InMemoryAuditSink(), b"test-key")


@pytest.fixture()
def expired(record, now) -> ResourceRecord:
    return ResourceRecord("rX", "u1", "high", now - timedelta(days=200), record.fields)


def test_expired_audit_reference_has_no_fields(store, expired, now):
    gw = make_gw(store)
    view = gw.access(Subject("au1", "auditor"), expired, Purpose.AUDIT_REVIEW, now)
    assert view.view == "audit_view"
    assert view.fields == {}  # 明文、掩码、令牌化字段一律不输出
    assert view.reference is not None and view.reference.startswith("ref_")
    blob = repr(view)
    for secret in SECRETS:
        assert secret not in blob


def test_reference_handle_reproducible_same_version(store, expired, now):
    gw = make_gw(store)
    auditor = Subject("au1", "auditor")
    v1 = gw.access(auditor, expired, Purpose.AUDIT_REVIEW, now)
    v2 = gw.access(auditor, expired, Purpose.AUDIT_REVIEW, now)
    assert v1.reference == v2.reference  # 同记录同策略版本：句柄稳定可复现


def test_reference_handle_distinguishes_policy_versions(store, policy, expired, now):
    gw = make_gw(store)
    auditor = Subject("au1", "auditor")
    before = gw.access(auditor, expired, Purpose.AUDIT_REVIEW, now).reference
    store.update(replace(policy, version=2))  # 仅版本变化，授权不变
    after = gw.access(auditor, expired, Purpose.AUDIT_REVIEW, now).reference
    assert before != after  # 新旧句柄可区分
    assert before.startswith("ref_") and after.startswith("ref_")


def test_reference_handle_distinguishes_records(store, record, expired, now):
    gw = make_gw(store)
    auditor = Subject("au1", "auditor")
    other = ResourceRecord("rY", "u1", "high", expired.created_at, record.fields)
    r1 = gw.access(auditor, expired, Purpose.AUDIT_REVIEW, now).reference
    r2 = gw.access(auditor, other, Purpose.AUDIT_REVIEW, now).reference
    assert r1 != r2


def test_expired_record_still_denied_for_normal_purposes(store, expired, agent, now):
    """既有保留期边界结论不变：普通用途访问超期记录一律拒绝。"""
    gw = make_gw(store)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(agent, expired, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("retention-expired")
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("a1", "analyst"), expired, Purpose.ANALYTICS, now)


def test_non_expired_audit_review_still_returns_masked_fields(store, record, now):
    """未超期记录的审计回看不受影响，仍按审计视图输出脱敏字段。"""
    gw = make_gw(store)
    view = gw.access(Subject("au1", "auditor"), record, Purpose.AUDIT_REVIEW, now)
    assert view.reference is None
    assert view.fields  # 非空：按 audit_view 脱敏输出
    for secret in SECRETS:
        assert secret not in str(view.fields)
