"""本地数据访问网关演示服务。"""

from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, HTTPException, Query

from gateway.errors import AccessDeniedError, AuditError, MaskingError
from gateway.audit import InMemoryAuditSink
from gateway.models import Purpose, ResourceRecord, Subject
from gateway.policy import Policy, PolicyStore, ViewRule
from gateway.service import AccessGateway

app = FastAPI(title="privacy-access-gateway")

_now = datetime.now(UTC)

POLICY = Policy(
    version=1,
    grants={
        ("agent", "service", "high"): "service_view",
        ("agent", "service", "medium"): "service_view",
        ("analyst", "analytics", "high"): "analytics_view",
        ("analyst", "analytics", "medium"): "analytics_view",
        ("auditor", "audit_review", "high"): "audit_view",
        ("auditor", "audit_review", "medium"): "audit_view",
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
            masked_fields={"phone": "last4", "id_card": "first1"},
            tokenized_fields=frozenset({"name"}),
        ),
    },
    retention_days={"medium": 365, "high": 90},
    required_attributes={"service_view": frozenset({"dept:cs"})},
)

STORE = PolicyStore(POLICY)
SINK = InMemoryAuditSink()
GATEWAY = AccessGateway(STORE, SINK, token_key=b"local-demo-key")

RECORDS: dict[str, ResourceRecord] = {
    "r1": ResourceRecord(
        "r1", "u1", "high", _now - timedelta(days=10),
        {"name": "张三", "phone": "13800001234", "id_card": "330102199001011234"},
    ),
    "r2": ResourceRecord(
        "r2", "u2", "high", _now - timedelta(days=120),  # 已超保留期
        {"name": "李四", "phone": "13900005678", "id_card": "330102199202022345"},
    ),
}


@app.get("/records/{record_id}")
def read_record(
    record_id: str,
    subject_id: str = Query(...),
    role: str = Query(...),
    purpose: Purpose = Query(...),
    attrs: str = Query("", description="逗号分隔的主体属性"),
):
    resource = RECORDS.get(record_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="record-not-found")
    subject = Subject(subject_id, role, frozenset(a for a in attrs.split(",") if a))
    try:
        view = GATEWAY.access(subject, resource, purpose)
    except AccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.reason) from exc
    except AuditError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except MaskingError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"record": {"record_id": view.record_id, "view": view.view, "fields": view.fields}}


@app.get("/audit")
def list_audit():
    return [
        {
            "timestamp": r.timestamp.isoformat(),
            "subject_id": r.subject_id,
            "role": r.role,
            "resource_id": r.resource_id,
            "purpose": r.purpose,
            "decision": r.decision,
            "reasons": list(r.reasons),
            "policy_version": r.policy_version,
        }
        for r in SINK.records()
    ]
