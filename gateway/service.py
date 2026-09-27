"""网关编排：取快照 -> 判定 -> 审计 -> 决策日志 -> 脱敏输出。"""

from __future__ import annotations

from datetime import UTC, datetime

from gateway import decision, masking
from gateway.audit import AuditSink, build_record
from gateway.decision_log import (
    DecisionLogSink,
    InMemoryDecisionLogSink,
    Outcome,
    build_entry,
)
from gateway.errors import AccessDeniedError, AuditError
from gateway.models import AccessView, Decision, Purpose, ResourceRecord, Subject
from gateway.policy import PolicyStore


class AccessGateway:
    """访问网关入口。

    每次请求只取一次策略快照，保证单次判定内部一致；
    审计写入失败一律不放行；脱敏失败不返回任何字段；
    每次判定恰好产生一条决策日志，日志写入失败不改变放行/拒绝结论。
    """

    def __init__(
        self,
        store: PolicyStore,
        sink: AuditSink,
        token_key: bytes,
        decision_log: DecisionLogSink | None = None,
    ) -> None:
        self._store = store
        self._sink = sink
        self._token_key = token_key
        self._decision_log: DecisionLogSink = decision_log or InMemoryDecisionLogSink()

    @property
    def decision_log(self) -> DecisionLogSink:
        return self._decision_log

    def _log(self, entry) -> None:
        """尽力写入决策日志：日志失败绝不改变既有放行/拒绝结论。"""
        try:
            self._decision_log.write(entry)
        except Exception:  # noqa: BLE001 - 日志不可影响判定结论
            pass

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
            self._log(build_entry(
                subject, resource.record_id, purpose, result, Outcome.AUDIT_FAILED, now,
            ))
            raise AuditError(f"audit-write-failed:{type(exc).__name__}") from exc

        if result.decision is not Decision.ALLOW:
            self._log(build_entry(
                subject, resource.record_id, purpose, result, Outcome.DENY, now,
            ))
            raise AccessDeniedError(tuple(result.reasons))

        if result.audit_reference_only:
            # 超期记录：仅可审计引用，不返回任何个人字段（明文/掩码/令牌化均不可），
            # 只给可复现的引用句柄。
            self._log(build_entry(
                subject, resource.record_id, purpose, result, Outcome.ALLOW, now,
            ))
            return AccessView(
                record_id=resource.record_id,
                view=result.view,  # type: ignore[arg-type]
                fields={},
                reference=masking.audit_reference_handle(
                    resource.record_id, result.policy_version, self._token_key,
                ),
            )

        view_rule = policy.views[result.view]  # type: ignore[index]
        try:
            masked = masking.apply_view(resource.fields, view_rule, self._token_key)
        except Exception:
            self._log(build_entry(
                subject, resource.record_id, purpose, result, Outcome.MASKING_FAILED, now,
            ))
            raise
        self._log(build_entry(
            subject, resource.record_id, purpose, result, Outcome.ALLOW, now,
        ))
        return AccessView(record_id=resource.record_id, view=result.view, fields=masked)  # type: ignore[arg-type]
