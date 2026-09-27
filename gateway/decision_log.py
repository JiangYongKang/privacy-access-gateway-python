"""运行期决策日志：每次访问判定恰好一条结构化日志，线程安全。

日志只携带标识与判定依据（主体标识、角色、资源标识、用途、结论、
策略版本、逐条原因），绝不包含任何原始敏感字段值。
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime

# 结局分类：放行 / 拒绝 / 审计写入失败 / 脱敏失败
OUTCOME_ALLOW = "allow"
OUTCOME_DENY = "deny"
OUTCOME_AUDIT_ERROR = "audit_error"
OUTCOME_MASKING_ERROR = "masking_error"

LOGGER_NAME = "gateway.decision"


@dataclass(frozen=True)
class DecisionLogEntry:
    """一条结构化决策日志（不含任何原始敏感值）。"""

    timestamp: datetime
    subject_id: str
    role: str
    resource_id: str
    purpose: str
    outcome: str  # allow / deny / audit_error / masking_error
    policy_version: int
    reasons: tuple[str, ...] = ()
    view: str | None = None
    reference: str | None = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "subject_id": self.subject_id,
            "role": self.role,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "outcome": self.outcome,
            "policy_version": self.policy_version,
            "reasons": list(self.reasons),
            "view": self.view,
            "reference": self.reference,
        }


class DecisionLogger:
    """决策日志发射器。

    底层使用标准 logging（自身线程安全），每条判定恰好发射一条记录；
    结构化字段同时放在 JSON 消息与 LogRecord 的 extra 属性上，
    便于本地用日志捕获（如 pytest caplog）按关键字段断言。
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(LOGGER_NAME)

    def emit(self, entry: DecisionLogEntry) -> None:
        payload = entry.to_dict()
        # extra 字段加 dl_ 前缀，避免与 LogRecord 内建属性冲突
        extras = {f"dl_{k}": v for k, v in payload.items()}
        self._logger.info(
            "access_decision %s", json.dumps(payload, ensure_ascii=False),
            extra=extras,
        )
