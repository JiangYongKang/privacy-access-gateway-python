"""策略并发更新与并发访问的一致性。"""

import threading
from dataclasses import replace

from gateway import AccessGateway, Purpose
from gateway.audit import InMemoryAuditSink
from gateway.errors import AccessDeniedError


def test_concurrent_policy_update_no_partial_state(store, policy, record, agent, now):
    """并发更新与判定：每次判定结论要么是旧策略要么是新策略，绝不出现半更新。"""
    sink = InMemoryAuditSink()
    gw = AccessGateway(store, sink, b"test-key")
    new_policy = replace(policy, version=2, grants={})  # 新版全部拒绝
    errors: list[Exception] = []

    def updater():
        for _ in range(200):
            store.update(new_policy)
            store.update(policy)

    def reader():
        for _ in range(200):
            try:
                gw.access(agent, record, Purpose.SERVICE, now)
            except AccessDeniedError:
                pass
            except Exception as exc:  # 不应出现其他异常
                errors.append(exc)

    threads = [threading.Thread(target=updater) for _ in range(2)] + [
        threading.Thread(target=reader) for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    # 每条审计记录都对应一个完整策略版本，结论与版本一致
    for rec in sink.records():
        if rec.policy_version == 1:
            assert rec.decision == "allow"
        else:
            assert rec.policy_version == 2 and rec.decision == "deny"


def test_concurrent_reads_consistent(store, record, agent, now):
    """同一资源并发访问结论一致。"""
    gw = AccessGateway(store, InMemoryAuditSink(), b"test-key")
    results = []

    def reader():
        for _ in range(50):
            results.append(gw.access(agent, record, Purpose.SERVICE, now))

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 400
    assert all(r == results[0] for r in results)
