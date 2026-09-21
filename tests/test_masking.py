"""脱敏与令牌化规则、确定性、越权字段不出现测试。"""

from __future__ import annotations

import pytest

from privacy_gateway.errors import MaskingError
from privacy_gateway.masking import FieldMasker
from privacy_gateway.models import DataRecord, FieldView, SensitivityLevel
from datetime import date

RECORD = DataRecord(
    record_id="r1",
    resource_type="customer",
    collected_on=date(2026, 9, 1),
    fields={"name": "Zhang", "phone": "13800001234", "id_card": "110101199001011234"},
    field_levels={
        "name": SensitivityLevel.PERSONAL,
        "phone": SensitivityLevel.SENSITIVE,
        "id_card": SensitivityLevel.SENSITIVE,
    },
)


def test_tokenization_is_deterministic_and_irreversible_looking():
    m1 = FieldMasker(token_salt="salt")
    m2 = FieldMasker(token_salt="salt")
    t1 = m1.tokenize("13800001234")
    t2 = m2.tokenize("13800001234")
    assert t1 == t2 and t1.startswith("tok:")
    assert "13800001234" not in t1
    # 不同盐产生不同令牌
    assert FieldMasker(token_salt="other").tokenize("13800001234") != t1
    # 不同值产生不同令牌
    assert m1.tokenize("13900000000") != t1


def test_mask_keeps_last_four_only():
    assert FieldMasker.mask_value("") == ""
    assert FieldMasker.mask_value("12") == "**"
    assert FieldMasker.mask_value("1234") == "****"
    assert FieldMasker.mask_value("123456") == "**3456"


def test_view_output_order_and_modes_are_stable():
    view = FieldView(
        "v",
        visible_fields=frozenset({"phone", "name", "id_card"}),
        masked_fields=frozenset({"name"}),
        tokenized_fields=frozenset({"phone", "id_card"}),
    )
    m = FieldMasker()
    out_a = m.apply(RECORD, view)
    out_b = m.apply(RECORD, view)
    assert [f.name for f in out_a] == ["id_card", "name", "phone"]  # 按名排序
    assert out_a == out_b
    modes = {f.name: f.mode for f in out_a}
    assert modes == {"name": "masked", "phone": "tokenized", "id_card": "tokenized"}


def test_fields_outside_view_never_appear():
    view = FieldView("v", frozenset({"name"}), masked_fields=frozenset({"name"}))
    out = FieldMasker().apply(RECORD, view)
    rendered = repr(out)
    assert [f.name for f in out] == ["name"]
    assert "110101199001011234" not in rendered
    assert "13800001234" not in rendered


def test_view_referencing_absent_field_fails_masking():
    view = FieldView("v", frozenset({"name", "nonexistent"}))
    with pytest.raises(MaskingError) as ei:
        FieldMasker().apply(RECORD, view)
    assert ei.value.reason == "unknown_field"


def test_invalid_view_definitions_rejected():
    with pytest.raises(MaskingError) as ei:
        FieldMasker._validate_view(
            FieldView("v", frozenset({"a"}),
                      masked_fields=frozenset({"a"}),
                      tokenized_fields=frozenset({"a"})))
    assert ei.value.reason == "ambiguous_field_mode"

    with pytest.raises(MaskingError) as ei:
        FieldMasker._validate_view(
            FieldView("v", frozenset({"a"}), masked_fields=frozenset({"b"})))
    assert ei.value.reason == "masked_not_visible"


def test_empty_salt_rejected():
    with pytest.raises(MaskingError):
        FieldMasker(token_salt="")
