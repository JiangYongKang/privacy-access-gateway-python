"""线程安全的版本化策略存储。

策略对象本身不可变（:class:`~privacy_gateway.models.Policy` 为 frozen），
存储只持有一个引用；发布即整包替换引用，判定方拿到的是一致快照，
因此不会出现半更新状态。历史快照永不被原地修改，可按
``policy_version`` 复现历史结论。
"""

from __future__ import annotations

import threading

from .errors import PolicyError
from .models import Policy
from .masking import FieldMasker


def validate_policy(policy: Policy) -> None:
    """发布前结构校验；任何非法项都抛 :class:`PolicyError`。"""
    if not policy.rules:
        raise PolicyError("policy must contain at least one rule",
                          reason="empty_rules")
    for rule in policy.rules:
        if not rule.rule_id:
            raise PolicyError("rule missing id", reason="empty_rule_id")
        if rule.field_view not in policy.views:
            raise PolicyError(
                f"rule '{rule.rule_id}' references unknown view "
                f"'{rule.field_view}'",
                reason="unknown_field_view",
            )
        if not rule.roles:
            raise PolicyError(
                f"rule '{rule.rule_id}' grants no roles",
                reason="empty_roles",
            )
        if not rule.allowed_purposes:
            raise PolicyError(
                f"rule '{rule.rule_id}' allows no purposes",
                reason="empty_purposes",
            )
    for name, view in policy.views.items():
        if view.name != name:
            raise PolicyError(
                f"view key '{name}' does not match view name '{view.name}'",
                reason="view_name_mismatch",
            )
        try:
            FieldMasker._validate_view(view)
        except Exception as exc:  # noqa: BLE001 - 统一转 PolicyError
            raise PolicyError(
                f"invalid view '{name}': {exc.message if hasattr(exc, 'message') else exc}",
                reason="invalid_view",
            ) from exc
    for rt, rule in policy.retention.items():
        if rule.resource_type != rt:
            raise PolicyError(
                f"retention key '{rt}' does not match resource_type "
                f"'{rule.resource_type}'",
                reason="retention_key_mismatch",
            )
        if rule.retention_days < 0:
            raise PolicyError(
                f"retention for '{rt}' has negative retention_days",
                reason="negative_retention",
            )


class PolicyStore:
    def __init__(self, initial: Policy | None = None) -> None:
        self._lock = threading.RLock()
        self._current: Policy | None = None
        if initial is not None:
            validate_policy(initial)
            self._current = initial

    def current(self) -> Policy:
        with self._lock:
            if self._current is None:
                raise PolicyError("no policy published", reason="policy_missing")
            return self._current

    def publish(self, policy: Policy) -> None:
        """原子发布新版本。

        先完成全部校验（校验失败时现有策略完全不受影响），再整包替换
        引用，因此不可能出现半更新状态；版本必须严格递增。
        """
        validate_policy(policy)
        with self._lock:
            if self._current is not None and policy.version <= self._current.version:
                raise PolicyError(
                    f"policy version {policy.version} is not newer "
                    f"than current {self._current.version}",
                    reason="version_conflict",
                )
            self._current = policy

    def snapshot(self) -> Policy:
        """取得当前策略快照引用（不可变，判定期间不会被改写）。"""
        return self.current()
