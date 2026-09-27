"""拒绝原因可解释聚合：多维度不满足时一次性列出全部原子原因。"""

from datetime import UTC, datetime, timedelta

import pytest

from gateway import AccessDeniedError, AccessGateway, Purpose, ReasonCode, Subject
from gateway.audit import InMemoryAuditSink
from gateway.models import ResourceRecord
from gateway.policy import Policy, PolicyStore, ViewRule

NOW = datetime(2026, 9, 21, tzinfo=UTC)
SECRETS = ("张三", "13800001234", "330102199001011234")


@pytest.fixture()
def split_policy() -> Policy:
    """agent/service 仅在 medium 上有授权，high 上无授权；
    service_view 要求属性 dept:cs。"""
    return Policy(
        version=1,
        grants={
            ("agent", "service", "medium"): "service_view",
            ("auditor", "audit_review", "high"): "audit_view",
        },
        views={
            "service_view": ViewRule("service_view", masked_fields={"phone": "last4"}),
            "audit_view": ViewRule("audit_view", tokenized_fields=frozenset({"name"})),
        },
        retention_days={"medium": 365, "high": 90},
        required_attributes={"service_view": frozenset({"dept:cs"})},
    )


@pytest.fixture()
def high_record() -> ResourceRecord:
    return ResourceRecord(
        "rH", "u1", "high", NOW - timedelta(days=10),
        {"name": "张三", "phone": "13800001234", "id_card": "330102199001011234"},
    )


def codes_of(exc: AccessDeniedError) -> list[str]:
    return [r.split(":", 1)[0] for r in exc.reasons]


def test_multi_dimension_deny_lists_all_reasons(split_policy, high_record):
    """无授权 + 缺属性同时存在时，两个维度的原因一次性列出。"""
    gw = AccessGateway(PolicyStore(split_policy), InMemoryAuditSink(), b"k")
    subject = Subject("s1", "agent")  # 缺少 dept:cs
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(subject, high_record, Purpose.SERVICE, NOW)
    codes = codes_of(ei.value)
    assert ReasonCode.NO_GRANT.value in codes
    assert ReasonCode.MISSING_ATTRIBUTES.value in codes
    assert len(codes) == 2  # 两个维度各一条，互不遗漏也不重复
    # 汇总字符串保持原有分号连接形式
    assert ei.value.reason == ";".join(ei.value.reasons)


def test_aggregated_reasons_have_stable_distinguishable_codes(split_policy, high_record):
    gw = AccessGateway(PolicyStore(split_policy), InMemoryAuditSink(), b"k")
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s1", "agent"), high_record, Purpose.SERVICE, NOW)
    codes = codes_of(ei.value)
    assert len(set(codes)) == len(codes)  # 原子原因彼此可区分
    assert set(codes) <= {c.value for c in ReasonCode}  # 均为稳定的枚举码


def test_single_dimension_deny_unchanged(split_policy, high_record):
    """只缺属性（授权存在）时仍只报属性维度，行为不回归。"""
    gw = AccessGateway(PolicyStore(split_policy), InMemoryAuditSink(), b"k")
    medium_record = ResourceRecord(
        "rM", "u1", "medium", NOW - timedelta(days=10), high_record.fields,
    )
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s1", "agent"), medium_record, Purpose.SERVICE, NOW)
    assert codes_of(ei.value) == [ReasonCode.MISSING_ATTRIBUTES.value]
    assert ei.value.reason.startswith("missing-attributes:dept:cs")


def test_aggregated_reasons_do_not_leak_sensitive_values(split_policy, high_record):
    gw = AccessGateway(PolicyStore(split_policy), InMemoryAuditSink(), b"k")
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s1", "agent"), high_record, Purpose.SERVICE, NOW)
    for secret in SECRETS:
        assert secret not in ei.value.reason
        assert secret not in repr(ei.value.reasons)


def test_expired_and_no_grant_aggregate(split_policy, high_record):
    """超期 + 无授权两类依据同样聚合，保留期拒绝结论不变。"""
    expired = ResourceRecord(
        "rOld", "u1", "high", NOW - timedelta(days=200), high_record.fields,
    )
    gw = AccessGateway(PolicyStore(split_policy), InMemoryAuditSink(), b"k")
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s1", "agent", frozenset({"dept:cs"})), expired,
                  Purpose.SERVICE, NOW)
    codes = codes_of(ei.value)
    assert codes[0] == ReasonCode.RETENTION_EXPIRED.value  # 保留期维度保持首位
    assert ReasonCode.NO_GRANT.value in codes
