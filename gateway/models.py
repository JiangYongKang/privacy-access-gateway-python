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


@dataclass(frozen=True)
class AccessView:
    """脱敏后的输出视图。"""

    record_id: str
    view: str
    fields: dict[str, str] = field(default_factory=dict)
