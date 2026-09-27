"""运行期决策日志：各结局路径下含判定依据、不含原始敏感值、线程安全。"""

import json
import logging
import threading
from dataclasses import replace

import pytest

from gateway import AccessDeniedError, AccessGateway, AuditError, MaskingError, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.decision_log import InMemoryDecisionLogSink, LoggingDecisionLogSink
from gateway.policy import ViewRule

SECRETS = ("张三", "13800001234", "330102199001011234")


def make_gw(store, sink=None, log=None):
    return AccessGateway(store, sink or InMemoryAuditSink(), b"test-key",
                         decision_log=log)


def test_allow_produces_structured_entry_with_basis(store, record, agent, now):
    log = InMemoryDecisionLogSink()
    gw = make_gw(store, log=log)
    gw.access(agent, record, Purpose.SERVICE, now)
    (entry,) = log.entries()
    assert entry.outcome == "allow" and entry.decision == "allow"
    assert entry.subject_id == "s1" and entry.role == "agent"
    assert entry.resource_id == "r1" and entry.purpose == "service"
    assert entry.policy_version == 1
    assert any(r.startswith("grant:") for r in entry.reasons)


def test_deny_produces_entry_with_reasons(store, record, now):
    log = InMemoryDecisionLogSink()
    gw = make_gw(store, log=log)
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    (entry,) = log.entries()
    assert entry.outcome == "deny" and entry.decision == "deny"
    assert any(r.startswith("no-grant") for r in entry.reasons)


def test_audit_failure_produces_entry(store, record, agent, now):
    class FailingSink:
        def write(self, record):
            raise IOError("disk full")

    log = InMemoryDecisionLogSink()
    gw = make_gw(store, sink=FailingSink(), log=log)
    with pytest.raises(AuditError):
        gw.access(agent, record, Purpose.SERVICE, now)
    (entry,) = log.entries()
    assert entry.outcome == "audit_failed"
    assert entry.decision == "allow"  # 判定本身是通过的，败在审计写入
    assert entry.policy_version == 1


def test_masking_failure_produces_entry(store, policy, record, agent, now):
    bad_view = ViewRule("service_view", masked_fields={"phone": "bogus-rule"})
    store.update(replace(policy, views={**policy.views, "service_view": bad_view}))
    log = InMemoryDecisionLogSink()
    gw = make_gw(store, log=log)
    with pytest.raises(MaskingError):
        gw.access(agent, record, Purpose.SERVICE, now)
    (entry,) = log.entries()
    assert entry.outcome == "masking_failed" and entry.decision == "allow"


def test_log_contains_no_raw_sensitive_values(store, record, agent, now):
    log = InMemoryDecisionLogSink()
    gw = make_gw(store, log=log)
    gw.access(agent, record, Purpose.SERVICE, now)
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    blob = repr(log.entries())
    for secret in SECRETS:
        assert secret not in blob


def test_log_failure_does_not_change_outcome(store, record, agent, now):
    class ExplodingLog:
        def write(self, entry):
            raise RuntimeError("log backend down")

    gw = make_gw(store, log=ExplodingLog())
    # 放行结论不因日志失败而改变
    assert gw.access(agent, record, Purpose.SERVICE, now).view == "service_view"
    # 拒绝结论也不因日志失败而改变
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)


def test_concurrent_access_exactly_one_entry_per_decision(store, record, agent, now):
    log = InMemoryDecisionLogSink()
    gw = make_gw(store, log=log)

    def reader():
        for _ in range(50):
            gw.access(agent, record, Purpose.SERVICE, now)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    entries = log.entries()
    assert len(entries) == 400  # 每条判定恰好一条，不丢不重
    assert all(e.outcome == "allow" for e in entries)


def test_logging_sink_emits_json_capturable_by_caplog(store, record, agent, now, caplog):
    gw = make_gw(store, log=LoggingDecisionLogSink())
    with caplog.at_level(logging.INFO, logger="gateway.decision"):
        gw.access(agent, record, Purpose.SERVICE, now)
    (record_log,) = [r for r in caplog.records if r.name == "gateway.decision"]
    payload = json.loads(record_log.getMessage())
    assert payload["outcome"] == "allow"
    assert payload["subject_id"] == "s1" and payload["role"] == "agent"
    assert payload["resource_id"] == "r1" and payload["purpose"] == "service"
    assert payload["policy_version"] == 1
    assert any(r.startswith("grant:") for r in payload["reasons"])
    for secret in SECRETS:
        assert secret not in record_log.getMessage()
