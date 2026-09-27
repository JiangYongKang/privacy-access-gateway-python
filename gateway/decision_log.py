"""运行期决策日志：每次访问判定产生一条结构化日志。

与审计留痕的区别：审计面向合规存档，决策日志面向运维排障，
覆盖放行、拒绝、审计写入失败、脱敏失败等全部结局。
日志只含标识与判定依据，绝不含原始敏感值。
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol

from gateway.models import DecisionResult, Purpose, Subject


class Outcome(str, Enum):
    """一次访问请求的最终结局（区别于判定结论本身）。"""

    ALLOW = "allow"                    # 放行
    DENY = "deny"                      # 拒绝
    AUDIT_FAILED = "audit_failed"      # 审计写入失败，访问被阻断
    MASKING_FAILED = "masking_failed"  # 脱敏失败，未输出任何字段


@dataclass(frozen=True)
class DecisionLogEntry:
    """一条结构化决策日志（不含任何原始敏感值）。"""

    timestamp: datetime
    subject_id: str
    role: str
    resource_id: str
    purpose: str
    outcome: str          # Outcome 值
    decision: str         # 判定结论 allow/deny
    reasons: tuple[str, ...]  # 逐条判定依据（原子原因码:细节）
    policy_version: int


class DecisionLogSink(Protocol):
    """决策日志写入端接口。"""

    def write(self, entry: DecisionLogEntry) -> None: ...


class InMemoryDecisionLogSink:
    """线程安全的内存决策日志存储，用于本地验证与断言。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[DecisionLogEntry] = []

    def write(self, entry: DecisionLogEntry) -> None:
        with self._lock:
            self._entries.append(entry)

    def entries(self) -> list[DecisionLogEntry]:
        with self._lock:
            return list(self._entries)


class LoggingDecisionLogSink:
    """把决策日志以单行 JSON 打到 stdlib logging，便于本地日志捕获（如 caplog）。

    logging 模块自身线程安全，可直接用于并发场景。
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("gateway.decision")

    def write(self, entry: DecisionLogEntry) -> None:
        payload = {
            "timestamp": entry.timestamp.isoformat(),
            "subject_id": entry.subject_id,
            "role": entry.role,
            "resource_id": entry.resource_id,
            "purpose": entry.purpose,
            "outcome": entry.outcome,
            "decision": entry.decision,
            "reasons": list(entry.reasons),
            "policy_version": entry.policy_version,
        }
        self._logger.info(json.dumps(payload, ensure_ascii=False))

    def entries(self) -> list[DecisionLogEntry]:
        return []


def build_entry(
    subject: Subject,
    resource_id: str,
    purpose: Purpose,
    result: DecisionResult,
    outcome: Outcome,
    now: datetime,
) -> DecisionLogEntry:
    """由判定结果与结局构造日志条目。只记录标识与依据，不含原始敏感值。"""
    return DecisionLogEntry(
        timestamp=now,
        subject_id=subject.subject_id,
        role=subject.role,
        resource_id=resource_id,
        purpose=purpose.value,
        outcome=outcome.value,
        decision=result.decision.value,
        reasons=result.reasons,
        policy_version=result.policy_version,
    )
