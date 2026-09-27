"""运行期决策日志：每次访问判定恰好一条结构化日志，线程安全且不丢不重。

日志只携带标识与判定依据（主体标识、角色、资源标识、用途、底层判定结论、
结局、策略版本、逐条原因），绝不包含任何原始敏感字段值。

输出端故障隔离：
- 主输出端（默认走标准 logging）失败时，自动降级到“安全兜底输出端”，
  保证每条判定恰好对应一条可辨认日志，且发射过程绝不向调用方抛错；
- 兜底路径只输出原有结构化负载外加静态故障标记，不拼接异常对象文本，
  避免异常信息夹带敏感内容，并发下带锁串行写入。
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

# 底层判定结论（可机读，独立于结局分类）
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"

# 结局分类：放行 / 拒绝 / 审计写入失败 / 脱敏失败
OUTCOME_ALLOW = "allow"
OUTCOME_DENY = "deny"
OUTCOME_AUDIT_ERROR = "audit_error"
OUTCOME_MASKING_ERROR = "masking_error"

# 主输出端失败、改由兜底输出端输出时，在负载上打的可机读标记
DELIVERED_FALLBACK = "fallback"
DELIVERED_PRIMARY = "primary"

LOGGER_NAME = "gateway.decision"


@dataclass(frozen=True)
class DecisionLogEntry:
    """一条结构化决策日志（不含任何原始敏感值）。

    decision 为本次判定本身的放行/拒绝结论；outcome 为请求最终结局分类。
    例如审计写入失败时 outcome=audit_error，但 decision 仍可能是 allow。
    """

    timestamp: datetime
    subject_id: str
    role: str
    resource_id: str
    purpose: str
    outcome: str  # allow / deny / audit_error / masking_error
    policy_version: int
    decision: str  # allow / deny：底层判定结论，与结局分类相互独立
    reasons: tuple[str, ...] = ()
    view: str | None = None
    reference: str | None = None
    log_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp.isoformat(),
            "subject_id": self.subject_id,
            "role": self.role,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "decision": self.decision,
            "outcome": self.outcome,
            "policy_version": self.policy_version,
            "reasons": list(self.reasons),
            "view": self.view,
            "reference": self.reference,
        }


class DecisionLogSink(Protocol):
    """决策日志输出端接口。实现可能抛异常，由 DecisionLogger 隔离。"""

    def write(self, payload: dict) -> None: ...


class LoggingDecisionSink:
    """默认主输出端：走标准 logging（其自身线程安全）。

    结构化字段同时放在 JSON 消息与 LogRecord 的 extra 属性上，
    便于本地用日志捕获（如 pytest caplog）按关键字段断言。
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(LOGGER_NAME)

    def write(self, payload: dict) -> None:
        # extra 字段加 dl_ 前缀，避免与 LogRecord 内建属性冲突
        extras = {f"dl_{k}": v for k, v in payload.items()}
        self._logger.info(
            "access_decision %s", json.dumps(payload, ensure_ascii=False),
            extra=extras,
        )


class SafeStreamFallbackSink:
    """安全兜底输出端：主输出端失败时保证日志不丢，且自身绝不抛错。

    - 只做一次带锁的文本写入，并发下各条日志互不穿插、不丢不重；
    - 文本仍是结构化 JSON（可机读），不含异常对象信息，避免异常文本
      夹带任何敏感内容；
    - 任何环节再失败都静默吞掉：日志故障永远不能影响请求结论。
    """

    def __init__(self, stream=None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._lock = threading.Lock()

    def write(self, payload: dict) -> None:
        try:
            line = "access_decision_fallback " + json.dumps(
                payload, ensure_ascii=False
            ) + "\n"
            with self._lock:
                self._stream.write(line)
                self._stream.flush()
        except Exception:  # noqa: BLE001, S110
            pass  # 兜底端自身故障只能静默，不能影响请求结论


class DecisionLogger:
    """决策日志发射器：主输出端失败自动降级，emit 绝不向调用方抛错。

    每条判定恰好发射一条记录：主输出端成功则只走主端；主端抛异常则改由
    安全兜底端输出（负载带 delivered=fallback 标记），不会两端重复记录。
    """

    def __init__(
        self,
        sink: DecisionLogSink | None = None,
        fallback: DecisionLogSink | None = None,
    ) -> None:
        self._sink = sink or LoggingDecisionSink()
        self._fallback = fallback or SafeStreamFallbackSink()
        self._fallback_lock = threading.Lock()

    def emit(self, entry: DecisionLogEntry) -> None:
        payload = entry.to_dict()
        payload["delivered"] = DELIVERED_PRIMARY
        try:
            self._sink.write(payload)
            return
        except Exception:  # noqa: BLE001, S110
            pass  # 日志故障隔离，不影响请求结论
        # 主端失败：改由安全兜底端输出同一条记录，不重复、不丢失。
        # 只用静态可机读标记，不拼接异常对象文本，避免夹带敏感内容。
        payload["delivered"] = DELIVERED_FALLBACK
        payload["primary_error"] = "decision-log-sink-failed"
        try:
            with self._fallback_lock:
                self._fallback.write(payload)
        except Exception:  # noqa: BLE001, S110
            pass  # 兜底端契约为不抛错，双保险
