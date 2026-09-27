"""决策日志输出端故障：对外结论与错误归类不被带偏，日志不丢不重、不泄漏。

覆盖：
- 日志主输出端失败时：放行仍返回脱敏视图；拒绝仍抛 AccessDeniedError；
  审计失败仍归类 AuditError；脱敏失败仍归类 MaskingError；
- 所有结局都带可机读的底层判定结论 decision；
- 主端失败自动转投兜底端；双端失败进死信队列，补发不重复；
- 故障异常文本（可能含敏感值）不进入任何日志或错误信息；
- 并发访问下每条判定恰好一条日志，不丢不重，线程安全。
"""

import io
import threading
from dataclasses import replace

import pytest

from gateway import (
    DECISION_ALLOW,
    DECISION_DENY,
    AccessDeniedError,
    AccessGateway,
    AuditError,
    DecisionLogEntry,
    DecisionLogger,
    MaskingError,
    Purpose,
    StderrFallbackSink,
    Subject,
)
from gateway.audit import InMemoryAuditSink
from gateway.decision_log import new_log_id
from gateway.policy import ViewRule

SECRETS = ("张三", "13800001234", "330102199001011234")


class RecordingSink:
    """线程安全的内存日志输出端。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.entries: list[DecisionLogEntry] = []

    def write(self, entry: DecisionLogEntry) -> None:
        with self._lock:
            self.entries.append(entry)

    def ids(self) -> set[str]:
        with self._lock:
            return {e.log_id for e in self.entries}


class ExplodingSink:
    """永远失败的输出端；异常文本可被注入敏感值以验证不泄漏。"""

    def __init__(self, message: str = "log-boom") -> None:
        self.message = message

    def write(self, entry: DecisionLogEntry) -> None:
        raise RuntimeError(self.message)


class SwitchSink(RecordingSink):
    """可切换健康状态的输出端，用于死信补发验证。"""

    def __init__(self) -> None:
        super().__init__()
        self.failing = True

    def write(self, entry: DecisionLogEntry) -> None:
        with self._lock:
            if self.failing:
                raise OSError("sink-down")
            self.entries.append(entry)


class FlakySink(RecordingSink):
    """每隔一次失败一次的输出端，用于并发下主/兜底两路投递验证。"""

    def __init__(self, fail_every: int = 2) -> None:
        super().__init__()
        self.calls = 0
        self.fail_every = fail_every

    def write(self, entry: DecisionLogEntry) -> None:
        with self._lock:
            self.calls += 1
            if self.calls % self.fail_every == 0:
                raise RuntimeError("intermittent")
            self.entries.append(entry)


class FailingAuditSink:
    def write(self, record) -> None:
        raise OSError("disk full")


def make_logger(primary, fallback=None):
    return DecisionLogger(primary, fallback=fallback)


def make_gw(store, audit_sink, dl):
    return AccessGateway(store, audit_sink, b"test-key", decision_logger=dl)


def _entry(decision=DECISION_ALLOW, outcome="allow", **kw):
    from datetime import UTC, datetime

    return DecisionLogEntry(
        timestamp=kw.get("timestamp", datetime(2026, 9, 21, tzinfo=UTC)),
        subject_id="s1",
        role="agent",
        resource_id="r1",
        purpose="service",
        decision=decision,
        outcome=outcome,
        policy_version=1,
        reasons=tuple(kw.get("reasons", ("grant:agent/service/high->view=service_view",))),
        view=kw.get("view", "service_view"),
        log_id=kw.get("log_id", new_log_id()),
    )


# ---------- 日志端失败：放行路径 ----------

def test_log_failure_allow_still_returns_masked_view(store, record, agent, now):
    cap = RecordingSink()
    dl = make_logger(ExplodingSink(), fallback=cap)
    gw = make_gw(store, InMemoryAuditSink(), dl)

    view = gw.access(agent, record, Purpose.SERVICE, now)  # 不外抛

    assert view.view == "service_view"
    assert view.fields  # 脱敏结果正常返回
    (entry,) = cap.entries  # 兜底端恰好一条
    assert entry.log_id
    assert entry.decision == DECISION_ALLOW
    assert entry.outcome == "allow"
    st = dl.stats()
    assert st["delivered"] == 1 and st["primary_failures"] == 1
    assert st["fallback_delivered"] == 1 and st["dead_pending"] == 0


# ---------- 日志端失败：拒绝路径 ----------

def test_log_failure_deny_still_raises_access_denied(store, record, now):
    cap = RecordingSink()
    dl = make_logger(ExplodingSink(), fallback=cap)
    gw = make_gw(store, InMemoryAuditSink(), dl)

    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("no-grant")  # 原拒绝结果保持可识别

    (entry,) = cap.entries
    assert entry.decision == DECISION_DENY
    assert entry.outcome == "deny"
    assert any(r.startswith("no-grant") for r in entry.reasons)
    assert entry.policy_version == 1


# ---------- 日志端失败：审计失败路径（底层判定分别为放行与拒绝） ----------

def test_log_failure_audit_error_kept_for_allowed_decision(store, record, agent, now):
    cap = RecordingSink()
    dl = make_logger(ExplodingSink(), fallback=cap)
    gw = make_gw(store, FailingAuditSink(), dl)

    with pytest.raises(AuditError) as ei:
        gw.access(agent, record, Purpose.SERVICE, now)
    assert "audit-write-failed" in str(ei.value)  # 仍是审计失败归类

    (entry,) = cap.entries
    assert entry.decision == DECISION_ALLOW  # 底层判定是放行，可机读
    assert entry.outcome == "audit_error"


def test_log_failure_audit_error_kept_for_denied_decision(store, record, now):
    cap = RecordingSink()
    dl = make_logger(ExplodingSink(), fallback=cap)
    gw = make_gw(store, FailingAuditSink(), dl)

    with pytest.raises(AuditError):  # 审计失败优先，不被改写成 AccessDeniedError
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)

    (entry,) = cap.entries
    assert entry.decision == DECISION_DENY  # 底层判定是拒绝，可机读
    assert entry.outcome == "audit_error"


# ---------- 日志端失败：脱敏失败路径 ----------

def test_log_failure_masking_error_kept(store, policy, record, agent, now):
    bad_view = ViewRule("service_view", masked_fields={"phone": "bogus-rule"})
    store.update(replace(policy, views={**policy.views, "service_view": bad_view}))
    cap = RecordingSink()
    dl = make_logger(ExplodingSink(), fallback=cap)
    gw = make_gw(store, InMemoryAuditSink(), dl)

    with pytest.raises(MaskingError):  # 脱敏失败归类不变
        gw.access(agent, record, Purpose.SERVICE, now)

    (entry,) = cap.entries
    assert entry.decision == DECISION_ALLOW
    assert entry.outcome == "masking_error"


# ---------- 所有结局都可机读底层判定结论 ----------

def test_every_outcome_carries_machine_readable_decision(store, policy, record, agent, now):
    cap = RecordingSink()
    dl = make_logger(ExplodingSink(), fallback=cap)
    audit_gw = make_gw(store, FailingAuditSink(), dl)
    gw = make_gw(store, InMemoryAuditSink(), dl)

    gw.access(agent, record, Purpose.SERVICE, now)  # allow
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)  # deny
    with pytest.raises(AuditError):
        audit_gw.access(agent, record, Purpose.SERVICE, now)  # audit_error
    bad_view = ViewRule("service_view", masked_fields={"phone": "bogus-rule"})
    store.update(replace(policy, views={**policy.views, "service_view": bad_view}))
    with pytest.raises(MaskingError):
        gw.access(agent, record, Purpose.SERVICE, now)  # masking_error

    by_outcome = {e.outcome: e for e in cap.entries}
    assert set(by_outcome) == {"allow", "deny", "audit_error", "masking_error"}
    for entry in by_outcome.values():
        assert entry.decision in (DECISION_ALLOW, DECISION_DENY)
        assert entry.log_id
        assert isinstance(entry.policy_version, int)
        assert entry.reasons  # 每条原因等依据保留
    assert by_outcome["allow"].decision == DECISION_ALLOW
    assert by_outcome["deny"].decision == DECISION_DENY
    assert by_outcome["audit_error"].decision == DECISION_ALLOW
    assert by_outcome["masking_error"].decision == DECISION_ALLOW


# ---------- 双端失败：死信不丢，补发不重 ----------

def test_both_sinks_fail_dead_letters_then_retry_once(store, record, agent, now):
    primary = SwitchSink()  # 初始故障
    fallback = ExplodingSink()
    dl = make_logger(primary, fallback=fallback)
    gw = make_gw(store, InMemoryAuditSink(), dl)

    view = gw.access(agent, record, Purpose.SERVICE, now)  # 双端故障也不影响放行
    assert view.fields
    (dead,) = dl.dead_letters()
    assert dead.outcome == "allow" and dead.decision == DECISION_ALLOW

    primary.failing = False  # 主端恢复（兜底端仍故障）
    assert dl.retry_dead_letters() == 1
    assert dl.dead_letters() == ()
    assert len(primary.entries) == 1
    # 再次补发不产生重复记录
    assert dl.retry_dead_letters() == 0
    assert len(primary.entries) == 1


def test_replay_same_entry_is_idempotent():
    cap = RecordingSink()
    dl = make_logger(cap)
    entry = _entry()
    dl.emit(entry)
    dl.emit(entry)  # 同一 log_id 重放
    assert len(cap.entries) == 1
    assert dl.stats()["delivered"] == 1


def test_emit_never_raises_when_both_sinks_break():
    dl = make_logger(ExplodingSink(), fallback=ExplodingSink())
    dl.emit(_entry())  # 不抛异常
    dl.emit(_entry())
    assert len(dl.dead_letters()) == 2


# ---------- 故障路径不泄漏敏感值（异常文本被丢弃，不转发） ----------

def test_failure_paths_never_leak_sensitive_values(store, record, agent, now):
    leak = "leak " + " ".join(SECRETS)

    # 场景 1：主端异常文本含敏感值，转投真实 stderr 兜底端
    buf = io.StringIO()
    dl = DecisionLogger(
        ExplodingSink(leak), fallback=StderrFallbackSink(stream=buf)
    )
    gw = make_gw(store, InMemoryAuditSink(), dl)
    gw.access(agent, record, Purpose.SERVICE, now)
    blob = buf.getvalue() + str(dl.stats())
    for secret in SECRETS:
        assert secret not in blob

    # 场景 2：双端均失败，死信条目与计数中也不含异常文本
    dl2 = DecisionLogger(ExplodingSink(leak), fallback=ExplodingSink(leak))
    gw2 = make_gw(store, InMemoryAuditSink(), dl2)
    gw2.access(agent, record, Purpose.SERVICE, now)
    import json

    dead_blob = json.dumps(
        [e.to_dict() for e in dl2.dead_letters()], ensure_ascii=False
    ) + str(dl2.stats())
    for secret in SECRETS:
        assert secret not in dead_blob


# ---------- 并发：日志不丢不重，线程安全 ----------

def test_concurrent_log_failures_no_loss_no_duplicate_allow(store, record, agent, now):
    primary = FlakySink()  # 一半调用失败
    fallback = RecordingSink()
    dl = make_logger(primary, fallback=fallback)
    gw = make_gw(store, InMemoryAuditSink(), dl)

    def reader():
        for _ in range(50):
            gw.access(agent, record, Purpose.SERVICE, now)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    st = dl.stats()
    assert st["delivered"] == 400
    assert st["dead_pending"] == 0
    primary_ids = primary.ids()
    fallback_ids = fallback.ids()
    assert primary_ids.isdisjoint(fallback_ids)  # 不重
    assert len(primary_ids) + len(fallback_ids) == 400  # 不丢
    assert all(e.decision == DECISION_ALLOW and e.outcome == "allow"
               for e in primary.entries + fallback.entries)


def test_concurrent_mixed_allow_deny_logged_exactly_once(store, record, agent, now):
    primary = FlakySink(fail_every=3)
    fallback = RecordingSink()
    dl = make_logger(primary, fallback=fallback)
    gw = make_gw(store, InMemoryAuditSink(), dl)
    errors: list[Exception] = []

    def reader():
        for i in range(50):
            try:
                if i % 2 == 0:
                    gw.access(agent, record, Purpose.SERVICE, now)
                else:
                    gw.access(
                        Subject("s9", "intruder"), record, Purpose.SERVICE, now
                    )
            except AccessDeniedError:
                pass
            except Exception as exc:  # noqa: BLE001 - 除拒绝外不应有任何异常（含日志故障）
                errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    entries = primary.entries + fallback.entries
    assert len(entries) == 400
    assert len({e.log_id for e in entries}) == 400  # 不重
    assert dl.stats()["delivered"] == 400 and dl.stats()["dead_pending"] == 0
    allow_entries = [e for e in entries if e.decision == DECISION_ALLOW]
    deny_entries = [e for e in entries if e.decision == DECISION_DENY]
    assert len(allow_entries) == 200 and len(deny_entries) == 200
    assert all(e.outcome == "allow" for e in allow_entries)
    assert all(e.outcome == "deny" for e in deny_entries)
