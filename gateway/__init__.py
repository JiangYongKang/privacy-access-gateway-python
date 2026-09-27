"""本地数据访问网关：访问判定、字段脱敏、审计留痕与运行期决策日志。"""

from gateway.decision_log import (
    DECISION_ALLOW,
    DECISION_DENY,
    DELIVERED_FALLBACK,
    DELIVERED_PRIMARY,
    OUTCOME_ALLOW,
    OUTCOME_AUDIT_ERROR,
    OUTCOME_DENY,
    OUTCOME_MASKING_ERROR,
    DecisionLogEntry,
    DecisionLogger,
    DecisionLogSink,
    LoggingDecisionSink,
    SafeStreamFallbackSink,
)
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
from gateway.reference import reference_handle
from gateway.service import AccessGateway

__all__ = [
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DELIVERED_FALLBACK",
    "DELIVERED_PRIMARY",
    "OUTCOME_ALLOW",
    "OUTCOME_AUDIT_ERROR",
    "OUTCOME_DENY",
    "OUTCOME_MASKING_ERROR",
    "AccessDeniedError",
    "AccessGateway",
    "AccessView",
    "AuditError",
    "Decision",
    "DecisionLogEntry",
    "DecisionLogSink",
    "DecisionLogger",
    "DecisionResult",
    "GatewayError",
    "LoggingDecisionSink",
    "MaskingError",
    "PolicyError",
    "Purpose",
    "ResourceRecord",
    "SafeStreamFallbackSink",
    "Subject",
    "reference_handle",
]
