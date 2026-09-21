"""字段级脱敏与确定性令牌化。

规则确定性：相同输入与视图永远得到相同输出；视图之外的字段
绝不会出现在输出中（由 :class:`FieldMasker` 只遍历可见字段保证）。
"""

from __future__ import annotations

import hashlib
import hmac

from .errors import MaskingError
from .models import DataRecord, FieldView, MaskedField

_TOKEN_PREFIX = "tok:"
_TOKEN_HEX_LEN = 16


class FieldMasker:
    """依据视图对记录字段执行明文/掩码/令牌化。"""

    def __init__(self, *, token_salt: str = "local-static-salt") -> None:
        if not token_salt:
            raise MaskingError("token salt must not be empty")
        self._salt = token_salt.encode("utf-8")

    def apply(self, record: DataRecord, view: FieldView) -> tuple[MaskedField, ...]:
        self._validate_view(view)

        # 字段按名称排序，保证输出顺序确定、可复现。
        result: list[MaskedField] = []
        for name in sorted(view.visible_fields):
            if name not in record.fields:
                # 不回显任何值，仅报缺失字段名（字段名本身不是敏感值）。
                raise MaskingError(
                    f"field '{name}' declared by view but absent on record",
                    reason="unknown_field",
                )
            if name not in record.field_levels:
                raise MaskingError(
                    f"field '{name}' has no declared sensitivity level",
                    reason="undeclared_sensitivity",
                )

            raw = record.fields[name]
            if name in view.tokenized_fields:
                result.append(MaskedField(name, "tokenized", self.tokenize(raw)))
            elif name in view.masked_fields:
                result.append(MaskedField(name, "masked", self.mask_value(raw)))
            else:
                result.append(MaskedField(name, "plain", raw))
        return tuple(result)

    def tokenize(self, value: str) -> str:
        """基于 HMAC-SHA256 的确定性、不可逆令牌。"""
        digest = hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256)
        return _TOKEN_PREFIX + digest.hexdigest()[:_TOKEN_HEX_LEN]

    @staticmethod
    def mask_value(value: str) -> str:
        """长度 <= 4 全部掩码；否则保留末 4 位，其余以 ``*`` 替换。"""
        if len(value) <= 4:
            return "*" * len(value)
        return "*" * (len(value) - 4) + value[-4:]

    @staticmethod
    def _validate_view(view: FieldView) -> None:
        overlap = view.masked_fields & view.tokenized_fields
        if overlap:
            raise MaskingError(
                "a field cannot be both masked and tokenized",
                reason="ambiguous_field_mode",
            )
        if not view.masked_fields <= view.visible_fields:
            raise MaskingError(
                "masked fields must be a subset of visible fields",
                reason="masked_not_visible",
            )
        if not view.tokenized_fields <= view.visible_fields:
            raise MaskingError(
                "tokenized fields must be a subset of visible fields",
                reason="tokenized_not_visible",
            )
