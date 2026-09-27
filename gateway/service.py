"""网关编排：取快照 -> 判定 -> 审计 -> 脱敏输出，并发射运行期决策日志。"""

from __future__ import annotations

from datetime import UTC, datetime

from gateway import decision, masking
from gateway.audit import AuditSink, build_record
from gateway.decision_log import (
    OUTCOME_ALLOW,
    OUTCOME_AUDIT_ERROR,
    OUTCOME_DENY,
    OUTCOME_MASKING_ERROR,
    DecisionLogEntry,
    DecisionLogger,
)
from gateway.errors import AccessDeniedError, AuditError, MaskingError
from gateway.models import AccessView, Decision, Purpose, ResourceRecord, Subject
from gateway.policy import PolicyStore
from gateway.reference import reference_handle


class AccessGateway:
    """访问网关入口。

    每次请求只取一次策略快照，保证单次判定内部一致；
    审计写入失败一律不放行；脱敏失败不返回任何字段；
    超期记录的审计引用不输出任何字段，仅返回可复现的引用句柄；
    每次判定恰好发射一条结构化决策日志（含独立的判定结论 decision）；
    日志输出端任何故障都被隔离，不改变放行/拒绝结论与错误归类。
    """

    def __init__(
        self,
        store: PolicyStore,
        sink: AuditSink,
        token_key: bytes,
        decision_logger: DecisionLogger | None = None,
    ) -> None:
        self._store = store
        self._sink = sink
        self._token_key = token_key
        self._log = decision_logger or DecisionLogger()

    def _emit(
        self,
        subject: Subject,
        resource: ResourceRecord,
        purpose: Purpose,
        result: decision.DecisionResult,
        now: datetime,
        outcome: str,
        reference: str | None = None,
    ) -> None:
        """发射一条决策日志。只含标识与依据，绝不含原始敏感值。"""
        self._log.emit(
            DecisionLogEntry(
                timestamp=now,
                subject_id=subject.subject_id,
                role=subject.role,
                resource_id=resource.record_id,
                purpose=purpose.value,
                # 判定本身的放行/拒绝结论，独立于结局分类与日志端故障
                decision=result.decision.value,
                outcome=outcome,
                policy_version=result.policy_version,
                reasons=result.reasons,
                view=result.view,
                reference=reference,
            )
        )

    def access(
        self,
        subject: Subject,
        resource: ResourceRecord,
        purpose: Purpose,
        now: datetime | None = None,
    ) -> AccessView:
        now = now or datetime.now(UTC)
        policy = self._store.snapshot()
        result = decision.evaluate(subject, resource, purpose, policy, now)

        # 审计先于放行：写入失败则拒绝访问，不静默放行。
        record = build_record(subject, resource.record_id, purpose, result, now)
        try:
            self._sink.write(record)
        except Exception as exc:  # noqa: BLE001 - 归一化为可区分错误
            self._emit(subject, resource, purpose, result, now, OUTCOME_AUDIT_ERROR)
            raise AuditError(f"audit-write-failed:{type(exc).__name__}") from exc

        if result.decision is not Decision.ALLOW:
            self._emit(subject, resource, purpose, result, now, OUTCOME_DENY)
            raise AccessDeniedError(";".join(result.reasons))

        # 超期记录：仅可审计引用，不输出任何字段（明文/掩码/令牌化均不可）。
        if result.audit_reference_only:
            ref = reference_handle(
                resource.record_id, result.policy_version, self._token_key
            )
            self._emit(
                subject, resource, purpose, result, now, OUTCOME_ALLOW, reference=ref
            )
            return AccessView(
                record_id=resource.record_id,
                view=result.view,  # type: ignore[arg-type]
                fields={},
                reference=ref,
            )

        view_rule = policy.views[result.view]  # type: ignore[index]
        try:
            masked = masking.apply_view(resource.fields, view_rule, self._token_key)
        except MaskingError:
            self._emit(subject, resource, purpose, result, now, OUTCOME_MASKING_ERROR)
            raise
        self._emit(subject, resource, purpose, result, now, OUTCOME_ALLOW)
        return AccessView(record_id=resource.record_id, view=result.view, fields=masked)  # type: ignore[arg-type]
