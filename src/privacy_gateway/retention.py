"""数据保留期计算与过期处置。

保留期边界：``record_age_days > retention_days`` 才算过期，
即恰好等于保留期的最后一天仍然可访问（边界可复现）。
"""

from __future__ import annotations

from datetime import date

from .models import DataRecord, Decision, RetentionRule


class RetentionService:
    """按记录采集日期与保留规则计算是否可访问。"""

    def evaluate(
        self,
        record: DataRecord,
        rule: RetentionRule | None,
        *,
        today: date,
    ) -> tuple[Decision, int, int | None]:
        """返回 ``(结论, 记录年龄天数, 保留天数)``。

        - 未配置保留规则：视为可访问（``ALLOW``），保留天数为 ``None``；
        - 保留期内：``ALLOW``；
        - 超过保留期：返回规则指定的过期动作
          （``AUDIT_ONLY`` 或 ``DENY``）。
        """
        age_days = (today - record.collected_on).days
        if rule is None:
            return Decision.ALLOW, age_days, None
        if age_days < 0:
            # 未来采集日期属于数据异常，保守拒绝。
            return Decision.DENY, age_days, rule.retention_days
        if age_days > rule.retention_days:
            return rule.expired_action, age_days, rule.retention_days
        return Decision.ALLOW, age_days, rule.retention_days
