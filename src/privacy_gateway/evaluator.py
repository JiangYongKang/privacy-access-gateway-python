"""访问判定引擎。

判定依据（缺一不可，任一缺失即拒绝并给出可区分原因）：

1. 主体角色：须有规则授予其任一角色；
2. 主体属性：须满足规则要求的全部属性；
3. 访问用途：须在规则允许用途内；
4. 资源敏感级别：每个字段都必须显式声明敏感级别；按规则视图
   可见字段的最高级别与规则上限比较（视图外字段不参与授权）；
5. 保留期：超过保留期按策略转为拒绝或仅可审计引用。

规则集合为有序元组；存在任意一条规则全部通过即放行，
否则拒绝并汇总确定性排序的原因码，保证结论可解释、可复现。
"""

from __future__ import annotations

from datetime import date

from .errors import PolicyError
from .models import (
    AccessDecision,
    AccessPurpose,
    AccessRule,
    DataRecord,
    Decision,
    DecisionEvidence,
    Policy,
    SensitivityLevel,
    Subject,
)
from .retention import RetentionService

_LEVEL_ORDER: dict[SensitivityLevel, int] = {
    SensitivityLevel.PUBLIC: 0,
    SensitivityLevel.INTERNAL: 1,
    SensitivityLevel.PERSONAL: 2,
    SensitivityLevel.SENSITIVE: 3,
}

# 可区分的拒绝原因码
R_ROLE = "role_not_authorized"
R_ATTRIBUTE = "missing_required_attribute"
R_PURPOSE = "purpose_not_permitted"
R_SENSITIVITY = "sensitivity_exceeds_rule"
R_UNDECLARED = "undeclared_field_sensitivity"
R_NO_RULE = "no_applicable_rule"
R_POLICY_NOT_EFFECTIVE = "policy_not_yet_effective"
R_INVALID_SUBJECT = "invalid_subject"
R_INVALID_RECORD = "invalid_record"
R_RETENTION_EXPIRED_DENY = "retention_expired_denied"
R_RETENTION_AUDIT_ONLY = "retention_expired_audit_only"
R_FUTURE_COLLECTION = "future_collection_date"


def level_at_most(actual: SensitivityLevel, ceiling: SensitivityLevel) -> bool:
    return _LEVEL_ORDER[actual] <= _LEVEL_ORDER[ceiling]


class AccessEvaluator:
    def __init__(self, retention_service: RetentionService | None = None) -> None:
        self._retention = retention_service or RetentionService()

    # ------------------------------------------------------------------
    def evaluate(
        self,
        subject: Subject,
        record: DataRecord,
        purpose: AccessPurpose,
        policy: Policy,
        *,
        today: date,
    ) -> AccessDecision:
        reasons: list[str] = []

        # 0. 输入有效性与策略生效性（必要依据存在性检查）
        if not subject.subject_id:
            return self._deny(subject, record, purpose, policy, None,
                              [R_INVALID_SUBJECT], None, None)
        if not record.record_id or not record.resource_type:
            return self._deny(subject, record, purpose, policy, None,
                              [R_INVALID_RECORD], None, None)
        if today < policy.effective_from:
            return self._deny(subject, record, purpose, policy, None,
                              [R_POLICY_NOT_EFFECTIVE], None, None)

        # 策略结构校验：每条规则引用的视图必须存在（否则无法确定字段集合）
        for rule in policy.rules:
            if rule.field_view not in policy.views:
                raise PolicyError(
                    f"rule '{rule.rule_id}' references unknown view "
                    f"'{rule.field_view}'",
                    reason="unknown_field_view",
                )

        # 1. 资源敏感级别依据：每个字段都必须声明
        undeclared = sorted(set(record.fields) - set(record.field_levels))
        if undeclared or not record.field_levels:
            reasons.append(R_UNDECLARED)
            max_level: SensitivityLevel | None = None
        else:
            max_level = max(record.field_levels.values(), key=lambda lv: _LEVEL_ORDER[lv])

        # 2. 保留期判定（过期优先，无论角色如何都不可读明文）
        retention_rule = policy.retention.get(record.resource_type)
        ret_decision, age_days, retention_days = self._retention.evaluate(
            record, retention_rule, today=today
        )
        if age_days < 0:
            reasons.append(R_FUTURE_COLLECTION)
        retention_ok = ret_decision is Decision.ALLOW and age_days >= 0
        if not retention_ok:
            if ret_decision is Decision.AUDIT_ONLY:
                reasons.append(R_RETENTION_AUDIT_ONLY)
            elif age_days < 0:
                pass  # 已记录 future_collection
            else:
                reasons.append(R_RETENTION_EXPIRED_DENY)
            return self._deny(
                subject, record, purpose, policy, None, reasons,
                age_days, retention_days,
                decision=ret_decision if age_days >= 0 else Decision.DENY,
            )

        # 3. 规则匹配（依据维度聚合）。
        # 每个依据维度只要被任一规则满足即视为该维度成立；无规则完整匹配
        # 时，从失败的维度生成可区分原因，避免多规则互相干扰、原因混淆。
        if not policy.rules:
            reasons.append(R_NO_RULE)
        role_ok = purpose_ok = attr_ok = sens_ok = False
        matched: AccessRule | None = None
        for rule in policy.rules:
            view = policy.views[rule.field_view]
            visible_levels = [
                record.field_levels[f]
                for f in view.visible_fields
                if f in record.field_levels
            ]
            effective_max = (
                max(visible_levels, key=lambda lv: _LEVEL_ORDER[lv])
                if visible_levels
                else SensitivityLevel.PUBLIC
            )
            r_role = bool(rule.roles & subject.roles)
            r_attr = rule.required_attributes <= subject.attributes
            r_purpose = purpose in rule.allowed_purposes
            r_sens = max_level is not None and level_at_most(effective_max, rule.max_sensitivity)
            if r_role and r_attr and r_purpose and r_sens:
                matched = rule
                role_ok = attr_ok = purpose_ok = sens_ok = True
                break
            role_ok = role_ok or r_role
            attr_ok = attr_ok or r_attr
            purpose_ok = purpose_ok or r_purpose
            sens_ok = sens_ok or r_sens

        if matched is None and policy.rules:
            # 由失败维度生成可区分原因；维度全部成立却无完整匹配时
            # （依据分散在不同规则），回退为 no_applicable_rule。
            # 字段级别未声明时已给出根因，不再重复报敏感度维度。
            if not role_ok:
                reasons.append(R_ROLE)
            if not attr_ok:
                reasons.append(R_ATTRIBUTE)
            if not purpose_ok:
                reasons.append(R_PURPOSE)
            if not sens_ok and max_level is not None:
                reasons.append(R_SENSITIVITY)
            if role_ok and attr_ok and purpose_ok and sens_ok:
                reasons.append(R_NO_RULE)

        if matched is not None:
            evidence = DecisionEvidence(
                policy_version=policy.version,
                matched_rule_id=matched.rule_id,
                role_ok=True,
                attributes_ok=True,
                purpose_ok=True,
                sensitivity_ok=True,
                retention_ok=True,
                retention_days=retention_days,
                record_age_days=age_days,
                reasons=(),
            )
            return AccessDecision(
                decision=Decision.ALLOW,
                subject_id=subject.subject_id,
                record_id=record.record_id,
                purpose=purpose,
                view_name=matched.field_view,
                evidence=evidence,
            )

        return self._deny(
            subject, record, purpose, policy, None,
            sorted(set(reasons)), age_days, retention_days,
            role_ok=role_ok, attr_ok=attr_ok, purpose_ok=purpose_ok, sens_ok=sens_ok,
        )

    # ------------------------------------------------------------------
    def _deny(
        self,
        subject: Subject,
        record: DataRecord,
        purpose: AccessPurpose,
        policy: Policy,
        matched_rule_id: str | None,
        reasons: list[str],
        age_days: int | None,
        retention_days: int | None,
        *,
        decision: Decision = Decision.DENY,
        role_ok: bool = False,
        attr_ok: bool = False,
        purpose_ok: bool = False,
        sens_ok: bool = False,
        retention_ok: bool = False,
    ) -> AccessDecision:
        evidence = DecisionEvidence(
            policy_version=policy.version,
            matched_rule_id=matched_rule_id,
            role_ok=role_ok,
            attributes_ok=attr_ok,
            purpose_ok=purpose_ok,
            sensitivity_ok=sens_ok,
            retention_ok=retention_ok,
            retention_days=retention_days,
            record_age_days=age_days,
            reasons=tuple(sorted(set(reasons))),
        )
        return AccessDecision(
            decision=decision,
            subject_id=getattr(subject, "subject_id", "") or "",
            record_id=getattr(record, "record_id", "") or "",
            purpose=purpose,
            view_name=None,
            evidence=evidence,
        )
