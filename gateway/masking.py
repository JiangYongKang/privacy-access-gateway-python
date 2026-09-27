"""字段级脱敏与确定性令牌化。"""

from __future__ import annotations

import hashlib
import hmac

from gateway.errors import MaskingError
from gateway.policy import ViewRule

_MASK_RULES = ("full", "last4", "first1")


def _mask(value: str, rule: str) -> str:
    if rule == "full":
        return "***"
    if rule == "last4":
        return "***" + value[-4:] if len(value) >= 4 else "***"
    if rule == "first1":
        return value[0] + "***" if value else "***"
    raise MaskingError(f"unknown-mask-rule:{rule}")


def _tokenize(field: str, value: str, key: bytes) -> str:
    if not key:
        raise MaskingError("token-key-missing")
    digest = hmac.new(key, f"{field}={value}".encode(), hashlib.sha256).hexdigest()
    return f"tok_{digest[:24]}"


def audit_reference_handle(record_id: str, policy_version: int, key: bytes) -> str:
    """超期记录的审计引用句柄：不含任何个人字段，确定可复现。

    同一记录在同一策略版本下句柄稳定；策略版本变化后句柄随之改变，
    新旧句柄可区分。句柄为 HMAC 摘要，无法反推记录内容。
    """
    if not key:
        raise MaskingError("token-key-missing")
    msg = f"audit-ref|{record_id}|v{policy_version}".encode()
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return f"ref_{digest[:24]}"


def apply_view(fields: dict[str, str], rule: ViewRule, token_key: bytes) -> dict[str, str]:
    """按视图规则输出字段集合：明文 / 掩码 / 令牌化。

    仅输出视图声明的字段；未声明字段一律不出现在结果中。
    同一字段只按一种规则输出，优先级：明文 > 令牌化 > 掩码。
    """
    out: dict[str, str] = {}
    for name in sorted(rule.plain_fields):
        if name in fields:
            out[name] = fields[name]
    for name in sorted(rule.tokenized_fields):
        if name in out or name not in fields:
            continue
        out[name] = _tokenize(name, fields[name], token_key)
    for name in sorted(rule.masked_fields):
        if name in out or name not in fields:
            continue
        mask_rule = rule.masked_fields[name]
        if mask_rule not in _MASK_RULES:
            raise MaskingError(f"unknown-mask-rule:{mask_rule}")
        out[name] = _mask(fields[name], mask_rule)
    return out
