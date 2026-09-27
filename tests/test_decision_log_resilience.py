"""决策日志输出端故障隔离：不改变对外结论与失败归类，不丢不重、不泄漏。"""

import io
import json
import threading
from dataclasses import replace

import pytest

from gateway import (
    AccessDeniedError,
    AccessGateway,
    AuditError,
    DecisionLogger,
    MaskingError,
    Purpose,
    SafeStreamFallbackSink,
    Subject,
)
from gateway.audit import InMemoryAuditSink
from gateway.decision_log import DELIVERED_FALLBACK, DELIVERED_PRIMARY
from gateway.policy import PolicyStore, ViewRule

SECRETS = ("张三", "13800001234", "330102199001011234")


class RecordingSink:
    """线程安全的内存日志输出端，记录全部成功写入的负载。"""

    def __init__(self):
        self._lock = threading.Lock()
        self.payloads = []

    def write(self, payload):
        with self._lock:
            self.payloads.append(payload)


class FailingSink(RecordingSink):
    """主输出端：总是失败。异常文本刻意夹带敏感值，验证其不会被带出。"""

    def write(self, payload):
        raise RuntimeError(f"boom {SECRETS[0]} {SECRETS[1]} {SECRETS[2]}")


class FlakySink(RecordingSink):
    """主输出端：奇偶交替失败，用于并发下验证恰好一次投递。"""

    def __init__(self):
        super().__init__()
        self._calls = 0
        self._call_lock = threading.Lock()

    def write(self, payload):
        with self._call_lock:
            self._calls += 1
            fail = self._calls % 2 == 0
        if fail:
            raise OSError("intermittent log failure")
        with self._lock:
            self.payloads.append(payload)


def make_gw(store, audit_sink, primary, fallback):
    logger = DecisionLogger(primary, fallback)
    return AccessGateway(store, audit_sink, b"test-key", decision_logger=logger)


def test_log_sink_failure_allow_still_returns_masked_view(store, record, agent, now):
    """日志端失败：本应放行的请求仍正常返回脱敏结果。"""
    primary, fallback = FailingSink(), RecordingSink()
    gw = make_gw(store, InMemoryAuditSink(), primary, fallback)

    view = gw.access(agent, record, Purpose.SERVICE, now)  # 不抛异常

    assert view.view == "service_view"
    assert view.fields["phone"] == "***1234"
    assert view.fields["id_card"] == "***"
    assert view.fields["name"].startswith("tok_")
    assert primary.payloads == []  # 主端全失败
    (entry,) = fallback.payloads  # 兜底端恰好一条
    assert entry["outcome"] == "allow"
    assert entry["decision"] == "allow"
    assert entry["delivered"] == DELIVERED_FALLBACK
    assert entry["policy_version"] == 1
    assert any(r.startswith("grant:") for r in entry["reasons"])


def test_log_sink_failure_deny_keeps_identifiable_rejection(store, record, now):
    """日志端失败：本应拒绝的请求仍给出原来的可识别拒绝结果。"""
    primary, fallback = FailingSink(), RecordingSink()
    gw = make_gw(store, InMemoryAuditSink(), primary, fallback)

    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("no-grant:")

    (entry,) = fallback.payloads
    assert entry["outcome"] == "deny"
    assert entry["decision"] == "deny"
    assert entry["delivered"] == DELIVERED_FALLBACK
    assert any(r.startswith("no-grant") for r in entry["reasons"])


def test_log_sink_failure_audit_error_keeps_classification(store, record, agent, now):
    """日志端失败：审计写入失败仍归类为 AuditError，不被日志故障覆盖。"""

    class FailingAuditSink:
        def write(self, record):
            raise OSError("disk full")

    primary, fallback = FailingSink(), RecordingSink()
    gw = make_gw(store, FailingAuditSink(), primary, fallback)

    with pytest.raises(AuditError) as ei:
        gw.access(agent, record, Purpose.SERVICE, now)
    assert str(ei.value) == "audit-write-failed:OSError"

    (entry,) = fallback.payloads
    assert entry["outcome"] == "audit_error"
    assert entry["decision"] == "allow"
    assert entry["delivered"] == DELIVERED_FALLBACK


def test_log_sink_failure_masking_error_keeps_classification(
    store, policy, record, agent, now
):
    """日志端失败：脱敏失败仍归类为 MaskingError，不被日志故障覆盖。"""
    bad_view = ViewRule("service_view", masked_fields={"phone": "bogus-rule"})
    store.update(replace(policy, views={**policy.views, "service_view": bad_view}))

    primary, fallback = FailingSink(), RecordingSink()
    gw = make_gw(store, InMemoryAuditSink(), primary, fallback)

    with pytest.raises(MaskingError) as ei:
        gw.access(agent, record, Purpose.SERVICE, now)
    assert str(ei.value) == "unknown-mask-rule:bogus-rule"

    (entry,) = fallback.payloads
    assert entry["outcome"] == "masking_error"
    assert entry["decision"] == "allow"
    assert entry["delivered"] == DELIVERED_FALLBACK


def test_log_sink_failure_never_leaks_raw_values(store, record, agent, now):
    """主端异常夹带敏感值时：兜底负载、兜底文本与对外结果均不含原值。"""
    stream = io.StringIO()
    primary = FailingSink()
    gw = AccessGateway(
        store,
        InMemoryAuditSink(),
        b"test-key",
        decision_logger=DecisionLogger(primary, SafeStreamFallbackSink(stream)),
    )

    view = gw.access(agent, record, Purpose.SERVICE, now)

    blob = json.dumps(view.fields, ensure_ascii=False) + stream.getvalue()
    for secret in SECRETS:
        assert secret not in blob
    # 兜底端文本为可机读 JSON，且带有故障与投递标记
    line = stream.getvalue().strip()
    assert line.startswith("access_decision_fallback {")
    fallback_entry = json.loads(line.split(" ", 1)[1])
    assert fallback_entry["delivered"] == DELIVERED_FALLBACK
    assert fallback_entry["primary_error"] == "decision-log-sink-failed"


def test_both_sinks_broken_request_still_succeeds(store, record, agent, now):
    """主端与兜底端都失败时：请求结论依旧不受影响（兜底端自身不抛错）。"""

    class BrokenFallback:
        def write(self, payload):
            raise RuntimeError("fallback also down")

    gw = make_gw(store, InMemoryAuditSink(), FailingSink(), BrokenFallback())
    view = gw.access(agent, record, Purpose.SERVICE, now)
    assert view.fields  # 仍正常返回脱敏结果


def test_safe_stream_fallback_swallows_broken_stream():
    """兜底输出端面对坏流也不抛错，保证故障隔离契约。"""

    class BrokenStream:
        def write(self, text):
            raise OSError("stream closed")

        def flush(self):
            raise OSError("stream closed")

    sink = SafeStreamFallbackSink(BrokenStream())
    sink.write({"outcome": "allow", "decision": "allow"})  # 不抛异常即通过


def test_concurrent_flaky_sink_exactly_once_per_decision(store, record, agent, now):
    """并发 + 主端间歇失败：每次判定恰好一条可辨认日志，不丢不重。"""
    primary, fallback = FlakySink(), RecordingSink()
    gw = make_gw(store, InMemoryAuditSink(), primary, fallback)

    def reader():
        for _ in range(50):
            gw.access(agent, record, Purpose.SERVICE, now)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    primary_ids = [p["log_id"] for p in primary.payloads]
    fallback_ids = [p["log_id"] for p in fallback.payloads]

    # 主端与兜底端不重复投递同一条
    assert set(primary_ids).isdisjoint(fallback_ids)
    all_ids = primary_ids + fallback_ids
    assert len(all_ids) == 400          # 不丢
    assert len(set(all_ids)) == 400     # 不重
    for p in primary.payloads:
        assert p["delivered"] == DELIVERED_PRIMARY
        assert p["outcome"] == "allow" and p["decision"] == "allow"
    for p in fallback.payloads:
        assert p["delivered"] == DELIVERED_FALLBACK
        assert p["outcome"] == "allow" and p["decision"] == "allow"


def test_concurrent_mixed_outcomes_flaky_sink_exactly_once(
    store, policy, record, agent, now
):
    """并发混合四种结局 + 主端间歇失败：每判定恰好一条，结局归类不串。"""
    bad_view = ViewRule("service_view", masked_fields={"phone": "bogus-rule"})
    broken_policy = replace(policy, views={**policy.views, "service_view": bad_view})

    class FlakyAuditSink(InMemoryAuditSink):
        def __init__(self):
            super().__init__()
            self._n = 0
            self._n_lock = threading.Lock()

        def write(self, record):
            with self._n_lock:
                self._n += 1
                fail = self._n % 7 == 0
            if fail:
                raise OSError("disk full")
            super().write(record)

    primary, fallback = FlakySink(), RecordingSink()
    gw_good = make_gw(store, InMemoryAuditSink(), primary, fallback)
    gw_audit_fail = make_gw(store, FlakyAuditSink(), primary, fallback)
    gw_mask_fail = make_gw(
        PolicyStore(broken_policy),
        InMemoryAuditSink(),
        primary,
        fallback,
    )
    intruder = Subject("s9", "intruder")

    def worker():
        for i in range(50):
            kind = i % 4
            try:
                if kind == 0:
                    gw_good.access(agent, record, Purpose.SERVICE, now)
                elif kind == 1:
                    gw_audit_fail.access(agent, record, Purpose.SERVICE, now)
                elif kind == 2:
                    with pytest.raises(AccessDeniedError):
                        gw_good.access(intruder, record, Purpose.SERVICE, now)
                else:
                    with pytest.raises(MaskingError):
                        gw_mask_fail.access(agent, record, Purpose.SERVICE, now)
            except AuditError:
                pass

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    all_entries = primary.payloads + fallback.payloads
    assert len(all_entries) == 8 * 50
    ids = [e["log_id"] for e in all_entries]
    assert len(set(ids)) == len(ids)  # 不重
    # 每个结局与其底层判定结论的对应关系不串
    by_outcome = {}
    for e in all_entries:
        by_outcome.setdefault(e["outcome"], set()).add(e["decision"])
    assert by_outcome["allow"] == {"allow"}
    assert by_outcome["deny"] == {"deny"}
    assert by_outcome["audit_error"] == {"allow"}
    assert by_outcome["masking_error"] == {"allow"}
