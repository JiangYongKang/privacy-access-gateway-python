"""可区分的错误类型定义。"""


class GatewayError(Exception):
    """网关错误基类。"""


class AccessDeniedError(GatewayError):
    """访问被拒绝，携带可区分的拒绝原因。

    ``reasons`` 为全部不满足维度的原子原因（``<code>:<detail>``），
    ``reason`` 为分号连接的汇总字符串，保持原有归类方式不变。
    """

    def __init__(self, reason: str | tuple[str, ...] | list[str]) -> None:
        reasons = (reason,) if isinstance(reason, str) else tuple(reason)
        self.reasons: tuple[str, ...] = reasons
        self.reason: str = ";".join(reasons)
        super().__init__(self.reason)


class MaskingError(GatewayError):
    """字段脱敏或令牌化失败。"""


class AuditError(GatewayError):
    """审计写入失败。"""


class PolicyError(GatewayError):
    """策略缺失或非法。"""
