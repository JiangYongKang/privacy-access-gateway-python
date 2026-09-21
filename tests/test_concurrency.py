"""策略原子发布、并发判定一致性、无半更新状态测试。"""

from __future__ import annotations

import threading
from datetime import date

from privacy_gateway.errors import PolicyError
from privacy_gateway.models import AccessPurpose, Decision
from tests.factories import (
    build_gateway,
    customer_record,
    full_policy,
    support_subject,
)

TODAY = date(2026, 9, 21)


def test_concurrent_reads_while_publishing_never_see_half_state():
    gw, store, _ = build_gateway()
    record = customer_record()
    decisions: list[str] = []
    evidence_versions: list[int] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def reader() -> None:
        barrier.wait()
        for _ in range(200):
            try:
                resp = gw.access(support_subject(), record,
                                 AccessPurpose.SUPPORT, today=TODAY)
                decisions.append(resp.decision.decision.value)
                evidence_versions.append(resp.decision.evidence.policy_version)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def publisher() -> None:
        barrier.wait()
        for v in range(2, 52):
            store.publish(full_policy(version=v))

    threads = [threading.Thread(target=reader) for _ in range(7)]
    threads.append(threading.Thread(target=publisher))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert decisions, "no decisions recorded"
    # 所有成功结论只能是 allow；证据版本必须与当时发布的完整版本一致
    assert set(decisions) == {"allow"}
    assert set(evidence_versions) <= set(range(1, 52))


def test_stale_or_equal_version_publish_is_rejected_and_state_unchanged():
    gw, store, _ = build_gateway()
    v1 = store.current()
    # 相同版本拒绝
    try:
        store.publish(full_policy(version=1))
        raise AssertionError("expected PolicyError")
    except PolicyError as ei:
        assert ei.reason == "version_conflict"
    # 旧版本拒绝
    try:
        store.publish(full_policy(version=0))
        raise AssertionError("expected PolicyError")
    except PolicyError as ei:
        assert ei.reason == "version_conflict"
    # 现状未被污染
    assert store.current() is v1


def test_invalid_policy_publish_leaves_current_policy_intact():
    gw, store, _ = build_gateway()
    v1 = store.current()
    # 规则引用不存在的视图 -> 发布被拒，现状不变
    from privacy_gateway.models import Policy
    broken = Policy(
        version=2, effective_from=v1.effective_from,
        rules=v1.rules, views={}, retention=v1.retention,
    )
    try:
        store.publish(broken)
        raise AssertionError("expected PolicyError")
    except PolicyError as ei:
        assert ei.reason == "unknown_field_view"
    assert store.current() is v1

    # 网关仍可正常判定（无残留部分状态）
    resp = gw.access(support_subject(), customer_record(),
                     AccessPurpose.SUPPORT, today=TODAY)
    assert resp.decision.decision is Decision.ALLOW


def test_snapshot_is_immutable_for_duration_of_decision():
    """判定期间持有的快照不受后续 publish 影响（结论一致）。"""
    gw, store, _ = build_gateway()
    snap = store.snapshot()
    store.publish(full_policy(version=2))
    store.publish(full_policy(version=3))
    # 旧快照仍完整可用
    assert snap.version == 1
    assert snap.rules and snap.views and snap.retention
