"""测试夹具工厂：构造确定性的主体、记录、策略、网关。"""

from __future__ import annotations

from datetime import date, datetime, timezone

from privacy_gateway.audit import InMemoryAuditSink
from privacy_gateway.gateway import PrivacyGateway
from privacy_gateway.masking import FieldMasker
from privacy_gateway.models import (
    AccessPurpose,
    AccessRule,
    DataRecord,
    Decision,
    FieldView,
    Policy,
    RetentionRule,
    SensitivityLevel,
    Subject,
)
from privacy_gateway.policy_store import PolicyStore

SENSITIVE_ID_CARD = "110101199001011234"
RAW_PHONE = "13800001234"


def support_view(*, with_phone: bool = False) -> FieldView:
    if with_phone:
        return FieldView(
            "support_view",
            visible_fields=frozenset({"name", "phone"}),
            masked_fields=frozenset({"name"}),
            tokenized_fields=frozenset({"phone"}),
        )
    return FieldView(
        "support_view",
        visible_fields=frozenset({"name"}),
        masked_fields=frozenset({"name"}),
    )


def risk_view() -> FieldView:
    return FieldView(
        "risk_view",
        visible_fields=frozenset({"name", "id_card"}),
        tokenized_fields=frozenset({"id_card"}),
    )


def support_rule(view: str = "support_view", *, rule_id: str = "r-support") -> AccessRule:
    return AccessRule(
        rule_id=rule_id,
        roles=frozenset({"support"}),
        allowed_purposes=frozenset({AccessPurpose.SUPPORT}),
        max_sensitivity=SensitivityLevel.PERSONAL,
        required_attributes=frozenset({("dept", "cs")}),
        field_view=view,
    )


def risk_rule() -> AccessRule:
    return AccessRule(
        rule_id="r-risk",
        roles=frozenset({"risk_analyst"}),
        allowed_purposes=frozenset({AccessPurpose.SUPPORT, AccessPurpose.AUDIT}),
        max_sensitivity=SensitivityLevel.SENSITIVE,
        required_attributes=frozenset({("clearance", "high")}),
        field_view="risk_view",
    )


def make_policy(
    *,
    version: int = 1,
    rules: tuple[AccessRule, ...] | None = None,
    views: dict[str, FieldView] | None = None,
    retention_days: int = 30,
    expired_action: Decision = Decision.AUDIT_ONLY,
    effective_from: date = date(2026, 1, 1),
) -> Policy:
    sv = support_view()
    return Policy(
        version=version,
        effective_from=effective_from,
        rules=rules if rules is not None else (support_rule(),),
        views=views if views is not None else {"support_view": sv},
        retention={
            "customer": RetentionRule("customer", retention_days, expired_action)
        },
    )


def full_policy(*, retention_days: int = 30, version: int = 1) -> Policy:
    return make_policy(
        version=version,
        rules=(support_rule(), risk_rule()),
        views={"support_view": support_view(), "risk_view": risk_view()},
        retention_days=retention_days,
    )


def support_subject() -> Subject:
    return Subject(
        "s-support",
        frozenset({"support"}),
        frozenset({("dept", "cs")}),
    )


def risk_subject() -> Subject:
    return Subject(
        "s-risk",
        frozenset({"risk_analyst"}),
        frozenset({("clearance", "high")}),
    )


def customer_record(
    *,
    record_id: str = "rec-1",
    collected_on: date = date(2026, 9, 1),
    include_sensitive: bool = True,
) -> DataRecord:
    fields = {"name": "Zhang San", "phone": RAW_PHONE}
    levels = {"name": SensitivityLevel.PERSONAL, "phone": SensitivityLevel.SENSITIVE}
    if include_sensitive:
        fields["id_card"] = SENSITIVE_ID_CARD
        levels["id_card"] = SensitivityLevel.SENSITIVE
    return DataRecord(
        record_id=record_id,
        resource_type="customer",
        collected_on=collected_on,
        fields=fields,
        field_levels=levels,
    )


class FixedClock:
    """确定性时钟。"""

    def __init__(self, value: datetime | None = None) -> None:
        self.value = value or datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


def build_gateway(
    policy: Policy | None = None,
    *,
    audit_sink=None,
    id_factory=None,
    no_policy: bool = False,
):
    if no_policy:
        store = PolicyStore()
    else:
        store = PolicyStore(policy if policy is not None else full_policy())
    sink = audit_sink or InMemoryAuditSink()
    ids = id_factory or (lambda: "audit-fixed")
    gw = PrivacyGateway(
        policy_store=store,
        audit_sink=sink,
        masker=FieldMasker(token_salt="test-salt"),
        clock=FixedClock(),
        id_factory=ids,
    )
    return gw, store, sink
