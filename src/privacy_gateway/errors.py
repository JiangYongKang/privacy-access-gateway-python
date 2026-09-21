"""可区分的网关错误类型体系。

所有网关错误都携带稳定的 ``code``，便于审计与调用方区分；
错误字符串中不得包含原始敏感字段值。
"""


class GatewayError(Exception):
    """网关错误基类。"""

    code: str = "gateway_error"

    def __init__(self, message: str, *, reason: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason

    def __str__(self) -> str:
        if self.reason:
            return f"{self.code}: {self.message} ({self.reason})"
        return f"{self.code}: {self.message}"


class AccessDeniedError(GatewayError):
    """访问被拒绝（缺少依据 / 角色不允许 / 用途不允许 / 保留期）。"""

    code = "access_denied"


class MaskingError(GatewayError):
    """字段脱敏或令牌化失败。"""

    code = "masking_failed"


class AuditError(GatewayError):
    """审计留痕写入失败。"""

    code = "audit_failed"


class PolicyError(GatewayError):
    """策略非法或处于不可用状态（如半更新）。"""

    code = "policy_error"
