"""审计留痕：记录主体、资源、用途、结论与依据。"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from gateway.models import DecisionResult, Purpose, Subject


@dataclass(frozen=True)
class AuditRecord:
    """一条审计记录（不含任何原始敏感值）。"""

    timestamp: datetime
    subject_id: str
    role: str
    resource_id: str
    purpose: str
    decision: str
    reasons: tuple[str, ...]
    policy_version: int


class AuditSink(Protocol):
    """审计写入端接口。"""

    def write(self, record: AuditRecord) -> None: ...


class InMemoryAuditSink:
    """线程安全的内存审计存储，用于本地验证。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []

    def write(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)

    def records(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)


def build_record(
    subject: Subject,
    resource_id: str,
    purpose: Purpose,
    result: DecisionResult,
    now: datetime,
) -> AuditRecord:
    """由判定结果构造审计记录。只记录标识与依据，不含原始敏感值。"""
    return AuditRecord(
        timestamp=now,
        subject_id=subject.subject_id,
        role=subject.role,
        resource_id=resource_id,
        purpose=purpose.value,
        decision=result.decision.value,
        reasons=result.reasons,
        policy_version=result.policy_version,
    )
