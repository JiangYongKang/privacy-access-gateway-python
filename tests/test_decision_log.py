"""运行期决策日志：各结局路径均产出结构化日志，且不含原始敏感值。"""

import json
import logging
import threading
from dataclasses import replace

import pytest

from gateway import AccessDeniedError, AccessGateway, AuditError, MaskingError, Purpose, Subject
from gateway.audit import InMemoryAuditSink
from gateway.decision_log import LOGGER_NAME
from gateway.policy import ViewRule

SECRETS = ("张三", "13800001234", "330102199001011234")


def make_gw(store, sink=None):
    return AccessGateway(store, sink or InMemoryAuditSink(), b"test-key")


@pytest.fixture()
def caplog_decision(caplog):
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        yield caplog


def payloads(caplog):
    """解析全部决策日志的 JSON 负载。"""
    out = []
    for rec in caplog.records:
        if rec.name != LOGGER_NAME:
            continue
        assert rec.getMessage().startswith("access_decision ")
        out.append(json.loads(rec.getMessage().split(" ", 1)[1]))
    return out


def test_allow_emits_one_structured_log(store, record, agent, now, caplog_decision):
    gw = make_gw(store)
    gw.access(agent, record, Purpose.SERVICE, now)
    (entry,) = payloads(caplog_decision)
    assert entry["outcome"] == "allow"
    assert entry["decision"] == "allow"  # 判定本身结论独立可机读
    assert entry["log_id"]  # 每条日志带可辨认的唯一标识
    assert entry["subject_id"] == "s1" and entry["role"] == "agent"
    assert entry["resource_id"] == "r1" and entry["purpose"] == "service"
    assert entry["policy_version"] == 1 and entry["view"] == "service_view"
    assert any(r.startswith("grant:") for r in entry["reasons"])


def test_deny_emits_log_with_reasons(store, record, now, caplog_decision):
    gw = make_gw(store)
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    (entry,) = payloads(caplog_decision)
    assert entry["outcome"] == "deny"
    assert entry["decision"] == "deny"
    assert any(r.startswith("no-grant") for r in entry["reasons"])


def test_audit_failure_emits_log(store, record, agent, now, caplog_decision):
    class FailingSink:
        def write(self, record):
            raise IOError("disk full")

    gw = AccessGateway(store, FailingSink(), b"test-key")
    with pytest.raises(AuditError):
        gw.access(agent, record, Purpose.SERVICE, now)
    (entry,) = payloads(caplog_decision)
    assert entry["outcome"] == "audit_error"
    assert entry["decision"] == "allow"  # 失败结局仍可读底层判定


def test_masking_failure_emits_log(store, policy, record, agent, now, caplog_decision):
    bad_view = ViewRule("service_view", masked_fields={"phone": "bogus-rule"})
    store.update(replace(policy, views={**policy.views, "service_view": bad_view}))
    gw = make_gw(store)
    with pytest.raises(MaskingError):
        gw.access(agent, record, Purpose.SERVICE, now)
    (entry,) = payloads(caplog_decision)
    assert entry["outcome"] == "masking_error"
    assert entry["decision"] == "allow"


def test_logs_contain_no_raw_sensitive_values(store, record, agent, now, caplog_decision):
    gw = make_gw(store)
    gw.access(agent, record, Purpose.SERVICE, now)
    with pytest.raises(AccessDeniedError):
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    blob = "\n".join(
        rec.getMessage() + repr(sorted(rec.__dict__.items()))
        for rec in caplog_decision.records
    )
    for secret in SECRETS:
        assert secret not in blob


def test_logging_does_not_change_conclusions(store, record, agent, now, caplog_decision):
    """记日志不改变放行/拒绝结论：放行仍返回视图，拒绝仍抛出同一错误。"""
    gw = make_gw(store)
    view = gw.access(agent, record, Purpose.SERVICE, now)
    assert view.view == "service_view" and view.fields
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(Subject("s9", "intruder"), record, Purpose.SERVICE, now)
    assert ei.value.reason.startswith("no-grant")
    assert len(payloads(caplog_decision)) == 2  # 每次判定恰好一条


def test_concurrent_access_logs_exactly_one_per_decision(store, record, agent, now, caplog_decision):
    """并发访问：日志线程安全，每条判定恰好一条，不丢不重。"""
    gw = make_gw(store)

    def reader():
        for _ in range(50):
            gw.access(agent, record, Purpose.SERVICE, now)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    entries = payloads(caplog_decision)
    assert len(entries) == 400
    assert all(e["outcome"] == "allow" for e in entries)
    assert all(e["decision"] == "allow" for e in entries)
    ids = [e["log_id"] for e in entries]
    assert all(ids) and len(set(ids)) == 400  # 每条可辨认、不丢不重
