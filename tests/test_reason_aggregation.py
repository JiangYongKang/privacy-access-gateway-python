"""拒绝原因可解释聚合：多维度不满足时一次性列出全部原子原因。"""

from dataclasses import replace
from datetime import timedelta

import pytest

from gateway import AccessDeniedError, AccessGateway, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.models import ResourceRecord

SECRETS = ("张三", "13800001234", "330102199001011234")
KNOWN_PREFIXES = (
    "no-retention-rule:",
    "retention-expired:",
    "no-grant:",
    "view-undefined:",
    "missing-attributes:",
)


def make_gw(store):
    return AccessGateway(store, InMemoryAuditSink(), b"test-key")


def deny_reasons(store, subject, resource, purpose, now) -> list[str]:
    with pytest.raises(AccessDeniedError) as ei:
        make_gw(store).access(subject, resource, purpose, now)
    return ei.value.reason.split(";")


def test_no_grant_and_missing_attributes_aggregated(store, policy, now):
    """无匹配授权 + 缺少候选视图必要属性：两个维度一次列出。"""
    store.update(replace(policy, retention_days={"high": 90, "medium": 365}))
    medium = ResourceRecord("rM", "u1", "medium", now - timedelta(days=10), {})
    # (agent, service, medium) 无授权；(agent, service, high) 指向的视图要求 dept:cs
    reasons = deny_reasons(store, Subject("s2", "agent"), medium, Purpose.SERVICE, now)
    assert len(reasons) == 2
    assert any(r.startswith("no-grant:") for r in reasons)
    assert "missing-attributes:dept:cs" in reasons


def test_retention_expired_and_no_grant_aggregated(store, record, now):
    expired = ResourceRecord("rX", "u1", "high", now - timedelta(days=200), record.fields)
    reasons = deny_reasons(store, Subject("s9", "intruder"), expired, Purpose.SERVICE, now)
    assert len(reasons) == 2
    assert any(r.startswith("retention-expired:") for r in reasons)
    assert any(r.startswith("no-grant:") for r in reasons)


def test_retention_expired_and_missing_attributes_aggregated(store, record, now):
    expired = ResourceRecord("rX", "u1", "high", now - timedelta(days=200), record.fields)
    reasons = deny_reasons(store, Subject("s2", "agent"), expired, Purpose.SERVICE, now)
    assert len(reasons) == 2
    assert any(r.startswith("retention-expired:") for r in reasons)
    assert "missing-attributes:dept:cs" in reasons


def test_view_undefined_and_missing_attributes_aggregated(store, policy, record, agent, now):
    ghost_policy = replace(
        policy,
        grants={("agent", "service", "high"): "ghost_view"},
        required_attributes={"ghost_view": frozenset({"clearance:1", "dept:cs"})},
    )
    store.update(ghost_policy)
    reasons = deny_reasons(store, agent, record, Purpose.SERVICE, now)
    assert "view-undefined:ghost_view" in reasons
    # agent 具备 dept:cs，仅缺 clearance:1；多个缺失属性按字典序聚合在同一原子原因内
    assert "missing-attributes:clearance:1" in reasons
    assert len(reasons) == 2


def test_reason_codes_are_atomic_and_distinguishable(store, record, now):
    """每个维度用稳定、彼此可区分的原子原因标识表达。"""
    expired = ResourceRecord("rX", "u1", "high", now - timedelta(days=200), record.fields)
    reasons = deny_reasons(store, Subject("s9", "intruder"), expired, Purpose.SERVICE, now)
    prefixes = [next(p for p in KNOWN_PREFIXES if r.startswith(p)) for r in reasons]
    assert len(prefixes) == len(set(prefixes))  # 彼此可区分，无重复维度


def test_single_dimension_deny_still_single_reason(store, record, now):
    """只有一个维度不满足时，仍只给出一条原因（不回归）。"""
    reasons = deny_reasons(store, Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    assert len(reasons) == 1 and reasons[0].startswith("no-grant:")


def test_aggregated_reasons_do_not_leak_sensitive_values(store, record, now):
    expired = ResourceRecord("rX", "u1", "high", now - timedelta(days=200), record.fields)
    reasons = deny_reasons(store, Subject("s2", "agent"), expired, Purpose.SERVICE, now)
    blob = ";".join(reasons)
    for secret in SECRETS:
        assert secret not in blob
