"""核心数据模型：主体、资源、用途与判定结果。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Purpose(str, Enum):
    """访问用途。"""

    SERVICE = "service"          # 业务办理
    ANALYTICS = "analytics"      # 统计分析
    AUDIT_REVIEW = "audit_review"  # 合规审计回看


class Decision(str, Enum):
    """判定结论。"""

    ALLOW = "allow"
    DENY = "deny"


class ReasonCode(str, Enum):
    """原子拒绝/判定原因标识：稳定、彼此可区分。

    判定依据字符串的统一格式为 ``<code>:<detail>``，前缀即本枚举值，
    调用方可按前缀做机读断言，detail 部分只含非敏感参数。
    """

    NO_RETENTION_RULE = "no-retention-rule"    # 敏感级别缺少保留期规则
    RETENTION_EXPIRED = "retention-expired"    # 记录已超保留期
    NO_GRANT = "no-grant"                      # 角色-用途-敏感级别无匹配授权
    VIEW_UNDEFINED = "view-undefined"          # 授权指向的视图未定义
    MISSING_ATTRIBUTES = "missing-attributes"  # 缺少视图要求的主体属性
    GRANT = "grant"                            # 放行依据：命中的授权


@dataclass(frozen=True)
class Subject:
    """访问主体：角色 + 属性。"""

    subject_id: str
    role: str
    attributes: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ResourceRecord:
    """含敏感字段的数据记录。"""

    record_id: str
    owner_id: str
    sensitivity: str  # 敏感级别，如 low/medium/high
    created_at: datetime
    fields: dict[str, str]


@dataclass(frozen=True)
class DecisionResult:
    """一次判定的完整结论与依据，可复现。"""

    decision: Decision
    reasons: tuple[str, ...]
    policy_version: int
    view: str | None = None  # 允许时使用的权限视图名
    audit_reference_only: bool = False  # 超期记录：仅可审计引用，不返回任何字段


@dataclass(frozen=True)
class AccessView:
    """脱敏后的输出视图。"""

    record_id: str
    view: str
    fields: dict[str, str] = field(default_factory=dict)
    reference: str | None = None  # 超期仅审计引用时的可复现引用句柄
