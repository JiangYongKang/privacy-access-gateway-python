from datetime import UTC, datetime, timedelta

import pytest

from gateway.models import Purpose, ResourceRecord, Subject
from gateway.policy import Policy, PolicyStore, ViewRule

NOW = datetime(2026, 9, 21, tzinfo=UTC)


@pytest.fixture()
def now() -> datetime:
    return NOW


@pytest.fixture()
def policy() -> Policy:
    return Policy(
        version=1,
        grants={
            ("agent", "service", "high"): "service_view",
            ("analyst", "analytics", "high"): "analytics_view",
            ("auditor", "audit_review", "high"): "audit_view",
        },
        views={
            "service_view": ViewRule(
                "service_view",
                masked_fields={"phone": "last4", "id_card": "full"},
                tokenized_fields=frozenset({"name"}),
            ),
            "analytics_view": ViewRule(
                "analytics_view",
                tokenized_fields=frozenset({"name", "phone", "id_card"}),
            ),
            "audit_view": ViewRule(
                "audit_view",
                masked_fields={"phone": "last4"},
                tokenized_fields=frozenset({"name"}),
            ),
        },
        retention_days={"high": 90},
        required_attributes={"service_view": frozenset({"dept:cs"})},
    )


@pytest.fixture()
def store(policy: Policy) -> PolicyStore:
    return PolicyStore(policy)


@pytest.fixture()
def record() -> ResourceRecord:
    return ResourceRecord(
        "r1", "u1", "high", NOW - timedelta(days=10),
        {"name": "张三", "phone": "13800001234", "id_card": "330102199001011234"},
    )


@pytest.fixture()
def agent() -> Subject:
    return Subject("s1", "agent", frozenset({"dept:cs"}))
