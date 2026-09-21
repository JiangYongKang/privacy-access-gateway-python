"""网关编排：取快照 -> 判定 -> 审计 -> 脱敏输出。"""

from __future__ import annotations

from datetime import UTC, datetime

from gateway import decision, masking
from gateway.audit import AuditSink, build_record
from gateway.errors import AccessDeniedError, AuditError
from gateway.models import AccessView, Decision, Purpose, ResourceRecord, Subject
from gateway.policy import PolicyStore


class AccessGateway:
    """访问网关入口。

    每次请求只取一次策略快照，保证单次判定内部一致；
    审计写入失败一律不放行；脱敏失败不返回任何字段。
    """

    def __init__(self, store: PolicyStore, sink: AuditSink, token_key: bytes) -> None:
        self._store = store
        self._sink = sink
        self._token_key = token_key

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
            raise AuditError(f"audit-write-failed:{type(exc).__name__}") from exc

        if result.decision is not Decision.ALLOW:
            raise AccessDeniedError(";".join(result.reasons))

        view_rule = policy.views[result.view]  # type: ignore[index]
        masked = masking.apply_view(resource.fields, view_rule, self._token_key)
        return AccessView(record_id=resource.record_id, view=result.view, fields=masked)  # type: ignore[arg-type]
