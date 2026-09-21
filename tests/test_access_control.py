"""越权访问、主体属性/用途/敏感级别依据缺失的判定测试。"""

from __future__ import annotations

from datetime import date

import pytest

from privacy_gateway.errors import AccessDeniedError
from privacy_gateway.models import AccessPurpose, Decision, SensitivityLevel, Subject
from tests.factories import (
    SENSITIVE_ID_CARD,
    build_gateway,
    customer_record,
    full_policy,
    risk_subject,
    support_subject,
)

TODAY = date(2026, 9, 21)


def test_authorized_support_subject_gets_masked_name_only():
    gw, _, sink = build_gateway()
    resp = gw.access(support_subject(), customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert resp.decision.decision is Decision.ALLOW
    assert [f.name for f in resp.fields] == ["name"]
    assert all(f.mode == "masked" for f in resp.fields)
    # 越权字段绝不出现在响应中
    rendered = str(resp)
    assert "id_card" not in rendered
    assert SENSITIVE_ID_CARD not in rendered
    assert len(sink.entries()) == 1


def test_role_not_authorized_is_denied_and_audited():
    gw, _, sink = build_gateway()
    intruder = Subject("s-intruder", frozenset({"intern"}), frozenset({("dept", "cs")}))
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(intruder, customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert "role_not_authorized" in ei.value.reason
    entry = sink.entries()[-1]
    assert entry.decision == "deny"
    assert "role_not_authorized" in entry.detail
    assert SENSITIVE_ID_CARD not in repr(entry)


def test_missing_required_attribute_is_denied_with_distinct_reason():
    gw, _, _ = build_gateway()
    no_attrs = Subject("s-noattr", frozenset({"support"}), frozenset())
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(no_attrs, customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert "missing_required_attribute" in ei.value.reason
    # 角色本身没问题，原因必须可区分，不得笼统报 role
    assert "role_not_authorized" not in ei.value.reason


def test_purpose_not_permitted_is_denied_with_distinct_reason():
    gw, _, _ = build_gateway()
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(support_subject(), customer_record(), AccessPurpose.MARKETING, today=TODAY)
    assert "purpose_not_permitted" in ei.value.reason


def test_sensitive_level_exceeded_even_when_view_would_expose_it():
    # 视图试图暴露 id_card，但规则上限 personal -> 拒绝
    gw, store, _ = build_gateway()
    from tests.factories import make_policy, support_rule, support_view
    from privacy_gateway.models import FieldView

    view = FieldView("leaky_view", frozenset({"id_card"}), frozenset({"id_card"}))
    policy = make_policy(
        version=2,
        rules=(support_rule("leaky_view", rule_id="r-leak"),),
        views={"leaky_view": view},
    )
    store.publish(policy)
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(support_subject(), customer_record(), AccessPurpose.SUPPORT, today=TODAY)
    assert "sensitivity_exceeds_rule" in ei.value.reason


def test_undeclared_field_sensitivity_is_denied():
    gw, _, _ = build_gateway()
    record = customer_record()
    object.__setattr__(record, "field_levels", {"name": SensitivityLevel.PERSONAL})
    # phone/id_card 存在于 fields 但未声明级别 -> 必要依据缺失
    with pytest.raises(AccessDeniedError) as ei:
        gw.access(support_subject(), record, AccessPurpose.SUPPORT, today=TODAY)
    assert "undeclared_field_sensitivity" in ei.value.reason
    # 根因已明确，不得再附带含糊的敏感度维度原因
    assert "sensitivity_exceeds_rule" not in ei.value.reason


def test_decision_is_deterministic_across_repeated_calls():
    gw, _, _ = build_gateway()
    results = []
    for _ in range(5):
        resp = gw.access(support_subject(), customer_record(), AccessPurpose.SUPPORT, today=TODAY)
        results.append(tuple((f.name, f.mode, f.value) for f in resp.fields))
    assert len(set(results)) == 1


def test_high_clearance_risk_subject_allowed_sensitive_view():
    gw, _, _ = build_gateway()
    resp = gw.access(risk_subject(), customer_record(), AccessPurpose.AUDIT, today=TODAY)
    assert resp.decision.decision is Decision.ALLOW
    names = {f.name for f in resp.fields}
    assert names == {"name", "id_card"}
    idc = next(f for f in resp.fields if f.name == "id_card")
    assert idc.mode == "tokenized"
    assert SENSITIVE_ID_CARD != idc.value
