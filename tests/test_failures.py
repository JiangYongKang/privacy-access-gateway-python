"""异常链路：审计失败、脱敏失败与错误归类。"""

from dataclasses import replace

import pytest

from gateway import AccessGateway, AuditError, MaskingError, Purpose
from gateway.audit import InMemoryAuditSink
from gateway.errors import AccessDeniedError, GatewayError
from gateway.policy import ViewRule


class FailingSink:
    def write(self, record):
        raise IOError("disk full")


def test_audit_failure_blocks_access(store, record, agent, now):
    gw = AccessGateway(store, FailingSink(), b"test-key")
    with pytest.raises(AuditError) as ei:
        gw.access(agent, record, Purpose.SERVICE, now)
    assert "audit-write-failed" in str(ei.value)


def test_audit_failure_also_blocks_denied_requests(store, record, now):
    """即使判定为拒绝，审计失败也以 AuditError 上报，可区分。"""
    from gateway import Subject

    gw = AccessGateway(store, FailingSink(), b"test-key")
    with pytest.raises(AuditError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)


def test_masking_failure_returns_no_fields(store, policy, record, agent, now):
    bad_view = ViewRule("service_view", masked_fields={"phone": "bogus-rule"})
    bad_policy = replace(policy, views={**policy.views, "service_view": bad_view})
    store.update(bad_policy)
    sink = InMemoryAuditSink()
    gw = AccessGateway(store, sink, b"test-key")
    with pytest.raises(MaskingError):
        gw.access(agent, record, Purpose.SERVICE, now)
    # 判定已留痕，但未输出任何字段（异常中不携带字段）
    assert sink.records()[-1].decision == "allow"


def test_error_types_are_distinguishable():
    assert issubclass(AccessDeniedError, GatewayError)
    assert issubclass(AuditError, GatewayError)
    assert issubclass(MaskingError, GatewayError)
    assert not issubclass(AuditError, AccessDeniedError)
    assert not issubclass(MaskingError, AccessDeniedError)


def test_failed_update_leaves_policy_untouched(store, record, agent, now):
    gw = AccessGateway(store, InMemoryAuditSink(), b"test-key")
    with pytest.raises(TypeError):
        store.update("not-a-policy")
    # 策略未被污染，访问结论不变
    assert gw.access(agent, record, Purpose.SERVICE, now).view == "service_view"
