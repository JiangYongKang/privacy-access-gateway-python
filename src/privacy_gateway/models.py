"""核心领域模型：主体、资源、策略、判定结论、审计记录。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum


class SensitivityLevel(str, Enum):
    """资源字段/资源的敏感级别。"""

    PUBLIC = "public"
    INTERNAL = "internal"
    PERSONAL = "personal"        # 一般个人信息
    SENSITIVE = "sensitive"      # 个人敏感信息


class Decision(str, Enum):
    """访问判定结论。"""

    ALLOW = "allow"
    DENY = "deny"
    AUDIT_ONLY = "audit_only"    # 超过保留期：仅可审计引用，不可读明文


class AccessPurpose(str, Enum):
    """预定义访问用途。"""

    SUPPORT = "support"          # 客服支持
    ANALYTICS = "analytics"      # 分析
    MARKETING = "marketing"      # 营销
    AUDIT = "audit"              # 合规审计
    DATA_EXPORT = "data_export"  # 数据导出


@dataclass(frozen=True, slots=True)
class Subject:
    """访问主体。

    ``subject_id`` 用于审计；``roles`` 为角色集合；
    ``attributes`` 为主体属性（如部门、 clearance 等），必须与角色、
    资源敏感级别、用途共同参与判定。
    """

    subject_id: str
    roles: frozenset[str]
    attributes: frozenset[tuple[str, str]] = frozenset()


@dataclass(frozen=True, slots=True)
class DataRecord:
    """受保护的数据记录。

    ``collected_on`` 决定保留期起算；``fields`` 为字段名到值的映射；
    ``field_levels`` 声明每个字段的敏感级别；
    ``field_tags`` 声明字段标签（如 ``tokenizable``）。
    """

    record_id: str
    resource_type: str
    collected_on: date
    fields: dict[str, str]
    field_levels: dict[str, SensitivityLevel]
    field_tags: dict[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FieldView:
    """字段视图规则。

    ``visible_fields`` 为该视图允许返回的字段；
    ``masked_fields`` 中的字段以掩码输出；
    ``tokenized_fields`` 中的字段以确定性令牌输出。
    """

    name: str
    visible_fields: frozenset[str]
    masked_fields: frozenset[str] = frozenset()
    tokenized_fields: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RetentionRule:
    """保留期规则（按资源类型）。

    保留期内：按角色视图访问；
    超过保留期：``expired_action`` 决定不可访问或仅可审计引用。
    """

    resource_type: str
    retention_days: int
    expired_action: Decision = Decision.AUDIT_ONLY


@dataclass(frozen=True, slots=True)
class AccessRule:
    """单条访问授权规则。

    要求主体具备任一 ``roles`` 且属性包含全部 ``required_attributes``，
    用途在 ``allowed_purposes`` 中，且资源字段最高敏感级别不超过
    ``max_sensitivity``。
    """

    rule_id: str
    roles: frozenset[str]
    allowed_purposes: frozenset[AccessPurpose]
    max_sensitivity: SensitivityLevel
    required_attributes: frozenset[tuple[str, str]] = frozenset()
    field_view: str = "default"


@dataclass(frozen=True, slots=True)
class Policy:
    """不可变策略快照，带版本号与生效时间。"""

    version: int
    effective_from: date
    rules: tuple[AccessRule, ...]
    views: dict[str, FieldView]
    retention: dict[str, RetentionRule]


@dataclass(frozen=True, slots=True)
class DecisionEvidence:
    """判定依据，可解释、可复现（不得包含原始敏感值）。"""

    policy_version: int
    matched_rule_id: str | None
    role_ok: bool
    attributes_ok: bool
    purpose_ok: bool
    sensitivity_ok: bool
    retention_ok: bool
    retention_days: int | None
    record_age_days: int | None
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """一次完整访问判定的结论。"""

    decision: Decision
    subject_id: str
    record_id: str
    purpose: AccessPurpose
    view_name: str | None
    evidence: DecisionEvidence


@dataclass(frozen=True, slots=True)
class MaskedField:
    """脱敏后的单个字段。"""

    name: str
    mode: str            # plain / masked / tokenized
    value: str


@dataclass(frozen=True, slots=True)
class GatewayResponse:
    """网关返回：判定结论 + 脱敏后的字段集合。"""

    decision: AccessDecision
    fields: tuple[MaskedField, ...]
    audit_id: str | None = None


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """审计记录：主体、资源、用途、结论与依据；无原始敏感值。"""

    audit_id: str
    timestamp_iso: str
    subject_id: str
    record_id: str
    resource_type: str
    purpose: str
    decision: str
    policy_version: int
    evidence: DecisionEvidence
    detail: str = ""
