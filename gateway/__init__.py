"""本地数据访问网关：访问判定、字段脱敏与审计留痕。"""

from gateway.decision_log import DecisionLogEntry, Outcome
from gateway.errors import (
    AccessDeniedError,
    AuditError,
    GatewayError,
    MaskingError,
    PolicyError,
)
from gateway.models import (
    AccessView,
    Decision,
    DecisionResult,
    Purpose,
    ReasonCode,
    ResourceRecord,
    Subject,
)
from gateway.service import AccessGateway

__all__ = [
    "AccessDeniedError",
    "AccessGateway",
    "AccessView",
    "AuditError",
    "Decision",
    "DecisionLogEntry",
    "DecisionResult",
    "GatewayError",
    "MaskingError",
    "Outcome",
    "PolicyError",
    "Purpose",
    "ReasonCode",
    "ResourceRecord",
    "Subject",
]
