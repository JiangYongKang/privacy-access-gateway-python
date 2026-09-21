"""可区分的错误类型定义。"""


class GatewayError(Exception):
    """网关错误基类。"""


class AccessDeniedError(GatewayError):
    """访问被拒绝，携带可区分的拒绝原因。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class MaskingError(GatewayError):
    """字段脱敏或令牌化失败。"""


class AuditError(GatewayError):
    """审计写入失败。"""


class PolicyError(GatewayError):
    """策略缺失或非法。"""
