"""越权访问与判定一致性。"""

from datetime import datetime

import pytest

from gateway import AccessDeniedError, AccessGateway, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.models import ResourceRecord


def make_gw(store):
    return AccessGateway(store, InMemoryAuditSink(), b"test-key")


def test_allow_returns_deterministic_view(store, record, agent, now):
    gw = make_gw(store)
    v1 = gw.access(agent, record, Purpose.SERVICE, now)
    v2 = gw.access(agent, record, Purpose.SERVICE, now)
    assert v1 == v2  # 同输入同结论，可复现
    assert v1.view == "service_view"
    assert v1.fields["phone"] == "***1234"
    assert v1.fields["id_card"] == "***"
    assert v1.fields["name"].startswith("tok_")
    # 明文敏感值不出现在响应中
    assert "张三" not in str(v1.fields)
    assert "13800001234" not in str(v1.fields)


def test_deny_unknown_role(store, record, now):
    gw = make_gw(store)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("no-grant")


def test_deny_wrong_purpose(store, record, agent, now):
    gw = make_gw(store)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(agent, record, Purpose.ANALYTICS, now)
    assert "no-grant" in ei.value.reason


def test_deny_missing_attributes(store, record, now):
    gw = make_gw(store)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s2", "agent"), record, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("missing-attributes:dept:cs")


def test_deny_reason_does_not_leak_sensitive_values(store, record, now):
    gw = make_gw(store)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    for secret in ("张三", "13800001234", "330102199001011234"):
        assert secret not in ei.value.reason


def test_analytics_view_tokenizes_all_sensitive_fields(store, record, now):
    gw = make_gw(store)
    view = gw.access(Subject("a1", "analyst"), record, Purpose.ANALYTICS, now)
    assert all(v.startswith("tok_") for v in view.fields.values())
