"""FastAPI 适配层集成测试。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from privacy_gateway.app import create_app
from privacy_gateway.audit import FailingAuditSink
from tests.factories import SENSITIVE_ID_CARD, build_gateway

POLICY = {
    "version": 1,
    "effective_from": "2026-01-01",
    "rules": [{
        "rule_id": "r-support",
        "roles": ["support"],
        "allowed_purposes": ["support"],
        "max_sensitivity": "personal",
        "required_attributes": [["dept", "cs"]],
        "field_view": "support_view",
    }],
    "views": {"support_view": {"visible_fields": ["name"], "masked_fields": ["name"]}},
    "retention": {"customer": {"retention_days": 30, "expired_action": "audit_only"}},
}

REQUEST = {
    "subject": {"subject_id": "s1", "roles": ["support"], "attributes": [["dept", "cs"]]},
    "record": {
        "record_id": "rec1", "resource_type": "customer", "collected_on": "2026-09-10",
        "fields": {"name": "Zhang", "id_card": SENSITIVE_ID_CARD},
        "field_levels": {"name": "personal", "id_card": "sensitive"},
    },
    "purpose": "support",
    "today": "2026-09-21",
}


@pytest.fixture()
def client() -> TestClient:
    gw, _, _ = build_gateway(no_policy=True)
    app = create_app(gw)
    c = TestClient(app)
    r = c.post("/v1/policies", json=POLICY)
    assert r.status_code == 200
    return c


def test_allowed_access_returns_masked_view_with_evidence(client):
    r = client.post("/v1/access", json=REQUEST)
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["fields"] == [{"name": "name", "mode": "masked", "value": "*hang"}]
    assert body["evidence"]["matched_rule_id"] == "r-support"
    assert body["evidence"]["checks"] == {
        "role": True, "attributes": True, "purpose": True,
        "sensitivity": True, "retention": True}
    # 越权字段与原始值绝不出现在响应体
    assert "id_card" not in r.text
    assert SENSITIVE_ID_CARD not in r.text


def test_denied_access_envelope_is_distinct_and_safe(client):
    bad = {**REQUEST, "subject": {"subject_id": "s2", "roles": ["intern"], "attributes": []}}
    r = client.post("/v1/access", json=bad)
    assert r.status_code == 403
    body = r.json()
    assert body["error"]["code"] == "access_denied"
    reason = body["error"]["reason"]
    # 两类缺失依据必须都可区分地出现
    assert "role_not_authorized" in reason
    assert "missing_required_attribute" in reason
    assert SENSITIVE_ID_CARD not in r.text


def test_malformed_requests_return_400_without_payload_echo(client):
    r = client.post("/v1/access", json={})
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"
    r = client.post("/v1/access", json={**REQUEST, "purpose": "bogus"})
    assert r.status_code == 400


def test_policy_conflict_returns_409_and_leaves_state(client):
    r = client.post("/v1/policies", json=POLICY)  # 同版本
    assert r.status_code == 409
    assert r.json()["error"]["reason"] == "version_conflict"
    # 旧策略仍可用
    assert client.post("/v1/access", json=REQUEST).status_code == 200


def test_audit_failure_returns_503_and_no_data():
    gw, _, _ = build_gateway(audit_sink=FailingAuditSink())
    client = TestClient(create_app(gw))
    client.post("/v1/policies", json=POLICY)
    r = client.post("/v1/access", json=REQUEST)
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "audit_failed"
    assert SENSITIVE_ID_CARD not in r.text


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}
