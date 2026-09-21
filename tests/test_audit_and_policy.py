"""审计记录完整性、策略校验与错误分类测试。"""

from __future__ import annotations

from datetime import date

import pytest

from privacy_gateway.audit import InMemoryAuditSink
from privacy_gateway.errors import PolicyError
from privacy_gateway.models import (
    AccessPurpose,
    AccessRule,
    Decision,
    Policy,
    RetentionRule,
    SensitivityLevel,
)
from privacy_gateway.policy_store import PolicyStore, validate_policy
from tests.factories import (
    build_gateway,
    customer_record,
    full_policy,
    make_policy,
    support_subject,
)

TODAY = date(2026, 9, 21)


def test_audit_entry_records_subject_resource_purpose_decision_evidence():
    gw, _, sink = build_gateway()
    resp = gw.access(support_subject(), customer_record(),
                     AccessPurpose.SUPPORT, today=TODAY)
    entry = sink.entries()[-1]
    assert entry.audit_id == resp.audit_id
    assert entry.subject_id == "s-support"
    assert entry.record_id == "rec-1"
    assert entry.resource_type == "customer"
    assert entry.purpose == "support"
    assert entry.decision == "allow"
    assert entry.policy_version == 1
    ev = entry.evidence
    assert ev.matched_rule_id == "r-support"
    assert ev.role_ok and ev.attributes_ok and ev.purpose_ok
    assert ev.sensitivity_ok and ev.retention_ok
    assert ev.record_age_days == 20 and ev.retention_days == 30
    assert entry.timestamp_iso


def test_policy_store_without_policy_raises_distinct_error():
    store = PolicyStore()
    with pytest.raises(PolicyError) as ei:
        store.current()
    assert ei.value.reason == "policy_missing"


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda p: Policy(p.version, p.effective_from, (), p.views, p.retention),
         "empty_rules"),
        (lambda p: Policy(p.version, p.effective_from,
                          (AccessRule("x", frozenset(), frozenset({AccessPurpose.SUPPORT}),
                                      SensitivityLevel.PERSONAL, frozenset(), "support_view"),),
                          p.views, p.retention),
         "empty_roles"),
        (lambda p: Policy(p.version, p.effective_from,
                          (AccessRule("x", frozenset({"support"}), frozenset(),
                                      SensitivityLevel.PERSONAL, frozenset(), "support_view"),),
                          p.views, p.retention),
         "empty_purposes"),
        (lambda p: Policy(p.version, p.effective_from,
                          p.rules, p.views,
                          {"customer": RetentionRule("customer", -1, Decision.AUDIT_ONLY)}),
         "negative_retention"),
    ],
)
def test_invalid_policies_are_rejected(mutate, reason):
    broken = mutate(full_policy())
    with pytest.raises(PolicyError) as ei:
        validate_policy(broken)
    assert ei.value.reason == reason


def test_audit_sink_threadsafe_append_order():
    sink = InMemoryAuditSink()
    from privacy_gateway.models import AuditEntry, DecisionEvidence
    import threading

    def writer(start: int) -> None:
        for i in range(start, start + 100):
            ev = DecisionEvidence(1, None, False, False, False, False, False, None, None, ())
            sink.write(AuditEntry(
                audit_id=f"a{i}", timestamp_iso="t", subject_id="s",
                record_id="r", resource_type="customer", purpose="support",
                decision="deny", policy_version=1, evidence=ev,
            ))

    threads = [threading.Thread(target=writer, args=(i * 100,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {e.audit_id for e in sink.entries()}
    assert len(ids) == 400
