"""本地数据访问网关：访问判定、字段脱敏与审计留痕。"""

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
    "DecisionResult",
    "GatewayError",
    "MaskingError",
    "PolicyError",
    "Purpose",
    "ResourceRecord",
    "Subject",
]
