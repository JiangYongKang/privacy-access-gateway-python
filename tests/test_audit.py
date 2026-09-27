"""审计留痕内容与敏感值泄漏检查。"""

import pytest

from gateway import AccessGateway, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.errors import AccessDeniedError

SECRETS = ("张三", "13800001234", "330102199001011234")


def test_audit_records_basis(store, record, agent, now):
    sink = InMemoryAuditSink()
    gw = AccessGateway(store, sink, b"test-key")
    gw.access(agent, record, Purpose.SERVICE, now)
    (rec,) = sink.records()
    assert rec.subject_id == "s1" and rec.role == "agent"
    assert rec.resource_id == "r1" and rec.purpose == "service"
    assert rec.decision == "allow" and rec.policy_version == 1
    assert any(r.startswith("grant:") for r in rec.reasons)


def test_denied_access_is_audited(store, record, now):
    sink = InMemoryAuditSink()
    gw = AccessGateway(store, sink, b"test-key")
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    (rec,) = sink.records()
    assert rec.decision == "deny"
    assert any(r.startswith("no-grant") for r in rec.reasons)


def test_audit_log_contains_no_raw_sensitive_values(store, record, agent, now):
    sink = InMemoryAuditSink()
    gw = AccessGateway(store, sink, b"test-key")
    gw.access(agent, record, Purpose.SERVICE, now)
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    blob = repr(sink.records())
    for secret in SECRETS:
        assert secret not in blob
