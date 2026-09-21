"""访问策略与线程安全的策略存储（版本化快照）。"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ViewRule:
    """单个权限视图：可见字段与掩码规则。"""

    name: str
    plain_fields: frozenset[str] = frozenset()      # 明文可见字段
    masked_fields: dict[str, str] = field(default_factory=dict)  # 字段 -> 掩码规则名
    tokenized_fields: frozenset[str] = frozenset()  # 令牌化字段


@dataclass(frozen=True)
class Policy:
    """不可变策略快照。"""

    version: int
    # (role, purpose, sensitivity) -> 视图名
    grants: dict[tuple[str, str, str], str]
    views: dict[str, ViewRule]
    retention_days: dict[str, int]  # 敏感级别 -> 保留天数
    required_attributes: dict[str, frozenset[str]]  # 视图名 -> 必须具备的主体属性


class PolicyStore:
    """策略存储：读写加锁，更新整体替换，读取返回不可变快照。"""

    def __init__(self, initial: Policy) -> None:
        self._lock = threading.Lock()
        self._policy = initial

    def snapshot(self) -> Policy:
        """返回当前不可变策略快照；快照在判定期间不会被更新影响。"""
        with self._lock:
            return self._policy

    def update(self, policy: Policy) -> None:
        """整体替换策略。替换是原子的，不会出现半更新状态。"""
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy")
        with self._lock:
            self._policy = policy
