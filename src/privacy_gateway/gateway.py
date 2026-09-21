"""网关门面：编排 判定 -> 脱敏 -> 审计。

失败语义（任何失败都不返回明文数据，也不污染策略/状态）：

- 判定为 ``DENY``：先写审计，再抛 :class:`AccessDeniedError`；
- 判定为 ``AUDIT_ONLY``：写审计后返回仅含审计引用的空字段响应；
- 判定为 ``ALLOW`` 但脱敏失败：尝试写审计后抛 :class:`MaskingError`；
- 审计写入失败：一律抛 :class:`AuditError``，绝不静默放行；
- 策略存储不可用/策略错误：透传 :class:`PolicyError`。

并发安全：网关不持有请求级可变状态；每次判定抓取不可变策略快照，
策略发布是整包原子替换，因此同资源/同策略并发判定结论一致。
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import date, datetime, timezone
from typing import Callable

from .audit import AuditSink, build_audit_entry
from .errors import AccessDeniedError, AuditError, MaskingError
from .models import (
    AccessDecision,
    AccessPurpose,
    DataRecord,
    Decision,
    GatewayResponse,
    MaskedField,
    Subject,
)

_logger = logging.getLogger("privacy_gateway")


class PrivacyGateway:
    def __init__(
        self,
        *,
        policy_store,
        audit_sink: AuditSink,
        masker,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._store = policy_store
        self._audit = audit_sink
        self._masker = masker
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ids = id_factory or (lambda: uuid.uuid4().hex)
        self._log = logger or _logger
        self._audit_lock = threading.Lock()

        from .evaluator import AccessEvaluator

        self._evaluator = AccessEvaluator()

    # ------------------------------------------------------------------
    def access(
        self,
        subject: Subject,
        record: DataRecord,
        purpose: AccessPurpose,
        *,
        today: date | None = None,
    ) -> GatewayResponse:
        now = self._clock()
        today = today or now.date()

        # 1. 抓取不可变策略快照（之后策略即使发布新版也不影响本次判定）
        policy = self._store.snapshot()

        # 2. 判定（PolicyError 直接透传，不产生部分状态）
        decision = self._evaluator_evaluate(subject, record, purpose, policy, today)

        # 3. 按结论分流
        if decision.decision is Decision.DENY:
            self._write_audit(decision, record.resource_type, now,
                              detail=";".join(decision.evidence.reasons))
            self._log_decision(decision)
            raise AccessDeniedError(
                "access denied",
                reason=";".join(decision.evidence.reasons) or "denied",
            )

        if decision.decision is Decision.AUDIT_ONLY:
            audit_id = self._write_audit(
                decision, record.resource_type, now,
                detail=";".join(decision.evidence.reasons),
            )
            self._log_decision(decision)
            return GatewayResponse(decision=decision, fields=(), audit_id=audit_id)

        # ALLOW：脱敏（不泄漏视图外字段），审计成功后才返回数据
        view = policy.views[decision.view_name]  # 判定时已校验存在
        try:
            fields = self._masker.apply(record, view)
        except MaskingError as exc:
            # 脱敏失败：尽量留痕；审计也失败时以 AuditError 为准
            try:
                self._write_audit(decision, record.resource_type, now,
                                  detail=f"masking_failed:{exc.reason}")
            except AuditError:
                raise
            self._log_decision(decision, extra="masking_failed")
            raise

        audit_id = self._write_audit(decision, record.resource_type, now,
                                     detail=self._delivery_summary(fields))
        self._log_decision(decision, extra="delivered")
        return GatewayResponse(decision=decision, fields=fields, audit_id=audit_id)

    # ------------------------------------------------------------------
    def _evaluator_evaluate(self, subject, record, purpose, policy, today) -> AccessDecision:
        return self._evaluator.evaluate(
            subject, record, purpose, policy, today=today
        )

    def _write_audit(
        self,
        decision: AccessDecision,
        resource_type: str,
        now: datetime,
        *,
        detail: str = "",
    ) -> str:
        audit_id = self._ids()
        entry = build_audit_entry(
            decision,
            resource_type=resource_type,
            audit_id=audit_id,
            timestamp_iso=now.isoformat(),
            detail=detail,
        )
        # 单一审计锁保证审计条目的追加顺序与调用顺序一致
        with self._audit_lock:
            self._audit.write(entry)
        return audit_id

    @staticmethod
    def _delivery_summary(fields: tuple[MaskedField, ...]) -> str:
        # 只记录字段名与输出模式，绝不记录值
        return ",".join(f"{f.name}:{f.mode}" for f in fields)

    def _log_decision(self, decision: AccessDecision, *, extra: str = "") -> None:
        # 日志只含结构化依据（ID/用途/结论/原因/版本），不含任何字段值
        ev = decision.evidence
        self._log.info(
            "decision=%s subject=%s record=%s purpose=%s policy=v%s rule=%s "
            "role_ok=%s attrs_ok=%s purpose_ok=%s sensitivity_ok=%s retention_ok=%s "
            "age_days=%s retention_days=%s reasons=%s%s",
            decision.decision.value,
            decision.subject_id,
            decision.record_id,
            decision.purpose.value,
            ev.policy_version,
            ev.matched_rule_id,
            ev.role_ok,
            ev.attributes_ok,
            ev.purpose_ok,
            ev.sensitivity_ok,
            ev.retention_ok,
            ev.record_age_days,
            ev.retention_days,
            ",".join(ev.reasons),
            f" phase={extra}" if extra else "",
        )
