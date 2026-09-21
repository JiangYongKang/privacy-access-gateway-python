"""审计留痕。

- 每次判定都记录主体、资源、用途、结论与依据（:class:`AuditEntry`）；
- 审计写入失败时由调用方（网关）保证“不静默放行”；本模块只负责
  把失败显式抛出为 :class:`~privacy_gateway.errors.AuditError`；
- 审计内容只含 ID、用途、结论与结构化依据，不含任何原始敏感值。
"""

from __future__ import annotations

import threading

from .errors import AuditError
from .models import AccessDecision, AuditEntry


class AuditSink:
    """审计落盘接口。"""

    def write(self, entry: AuditEntry) -> None:
        raise NotImplementedError


class InMemoryAuditSink(AuditSink):
    """线程安全的本地内存审计存储（测试与本地运行用）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[AuditEntry] = []

    def write(self, entry: AuditEntry) -> None:
        if not entry.audit_id:
            raise AuditError("audit entry missing audit_id", reason="empty_audit_id")
        with self._lock:
            self._entries.append(entry)

    def entries(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._entries)


class FailingAuditSink(AuditSink):
    """始终失败的审计通道，用于验证“审计失败不静默放行”。"""

    def __init__(self, reason: str = "sink unavailable") -> None:
        self.reason = reason

    def write(self, entry: AuditEntry) -> None:
        raise AuditError("audit write failed", reason=self.reason)


def build_audit_entry(
    decision: AccessDecision,
    *,
    resource_type: str,
    audit_id: str,
    timestamp_iso: str,
    detail: str = "",
) -> AuditEntry:
    """根据判定结论构造审计记录（不含原始敏感值）。"""
    return AuditEntry(
        audit_id=audit_id,
        timestamp_iso=timestamp_iso,
        subject_id=decision.subject_id,
        record_id=decision.record_id,
        resource_type=resource_type,
        purpose=decision.purpose.value,
        decision=decision.decision.value,
        policy_version=decision.evidence.policy_version,
        evidence=decision.evidence,
        detail=detail,
    )
