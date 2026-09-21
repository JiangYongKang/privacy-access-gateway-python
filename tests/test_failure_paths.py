"""脱敏失败、审计失败、错误可区分分类、无敏感值泄漏测试。"""

from __future__ import annotations

from datetime import date

import pytest

from privacy_gateway.audit import FailingAuditSink, InMemoryAuditSink
from privacy_gateway.errors import (
    AccessDeniedError,
    AuditError,
    GatewayError,
    MaskingError,
    PolicyError,
)
from privacy_gateway.models import AccessPurpose, Decision, FieldView
from tests.factories import (
    SENSITIVE_ID_CARD,
    RAW_PHONE,
    build_gateway,
    customer_record,
    make_policy,
    support_rule,
    support_subject,
)

TODAY = date(2026, 9, 21)


def test_audit_failure_blocks_allowed_access_without_data_release():
    gw, _, _ = build_gateway(audit_sink=FailingAuditSink("disk full"))
    with pytest.raises(AuditError) as ei:
        gw.access(support_subject(), customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert ei.value.reason == "disk full"
    # 错误文本不得包含敏感值
    assert SENSITIVE_ID_CARD not in str(ei.value)


def test_audit_failure_on_deny_is_not_silently_swallowed():
    gw, _, _ = build_gateway(audit_sink=FailingAuditSink())
    from privacy_gateway.models import Subject
    intruder = Subject("x", frozenset({"nobody"}), frozenset())
    # 审计失败时抛 AuditError，而不是被“正常拒绝”掩盖
    with pytest.raises(AuditError):
        gw.access(intruder, customer_record(), AccessPurpose.SUPPORT, today=TODAY)


def test_masking_failure_raises_distinct_error_and_is_audited():
    # 视图声明了记录上不存在的字段 -> 脱敏失败
    broken_view = FieldView("broken", frozenset({"name", "ghost"}), frozenset({"name"}))
    policy = make_policy(
        version=2,
        rules=(support_rule("broken", rule_id="r-broken"),),
        views={"broken": broken_view},
    )
    sink = InMemoryAuditSink()
    gw, store, _ = build_gateway(audit_sink=sink)
    store.publish(policy)
    with pytest.raises(MaskingError) as ei:
        gw.access(support_subject(), customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert ei.value.reason == "unknown_field"
    # 脱敏失败也应留痕，且不返回数据
    assert sink.entries()[-1].detail.startswith("masking_failed")


def test_error_classes_are_distinguishable():
    assert {AccessDeniedError.code, MaskingError.code,
            AuditError.code, PolicyError.code} == {
        "access_denied", "masking_failed", "audit_failed", "policy_error"}
    for cls in (AccessDeniedError, MaskingError, AuditError, PolicyError):
        assert issubclass(cls, GatewayError)


def test_denied_response_and_logs_never_contain_raw_sensitive_values(caplog):
    import logging
    gw, _, sink = build_gateway()
    with caplog.at_level(logging.INFO, logger="privacy_gateway"):
        with pytest.raises(AccessDeniedError):
            gw.access(support_subject(), customer_record(),
                      AccessPurpose.MARKETING, today=TODAY)
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert log_text, "expected a decision log line"
    assert "purpose_not_permitted" in log_text          # 日志含判定依据
    assert SENSITIVE_ID_CARD not in log_text            # 但不含原始敏感值
    assert RAW_PHONE not in log_text
    for entry in sink.entries():
        assert SENSITIVE_ID_CARD not in repr(entry.evidence)


def test_failed_publish_does_not_mutate_policy_or_audit_state():
    sink = InMemoryAuditSink()
    gw, store, _ = build_gateway(audit_sink=sink)
    # 先有一次正常访问
    gw.access(support_subject(), customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert len(sink.entries()) == 1
    # 非法发布失败
    with pytest.raises(PolicyError):
        store.publish(make_policy(version=0))
    # 网关行为不变，审计历史不变
    gw.access(support_subject(), customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert len(sink.entries()) == 2
