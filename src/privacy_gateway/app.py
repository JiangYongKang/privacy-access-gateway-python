"""FastAPI 本地 HTTP 适配层。

- ``POST /v1/access``：提交主体/资源/用途，返回判定与脱敏字段；
- ``POST /v1/policies``：原子发布新策略版本；
- ``GET /healthz``：健康检查。

错误响应只携带错误码与原因码，绝不携带任何原始敏感字段值。
"""

from __future__ import annotations

from datetime import date

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .audit import InMemoryAuditSink
from .errors import AccessDeniedError, AuditError, GatewayError, MaskingError, PolicyError
from .gateway import PrivacyGateway
from .masking import FieldMasker
from .models import (
    AccessPurpose,
    AccessRule,
    DataRecord,
    Decision,
    FieldView,
    Policy,
    RetentionRule,
    SensitivityLevel,
    Subject,
)
from .policy_store import PolicyStore


def create_app(gateway: PrivacyGateway | None = None) -> FastAPI:
    app = FastAPI(title="privacy-access-gateway", version="0.1.0")

    if gateway is None:
        gateway = PrivacyGateway(
            policy_store=PolicyStore(),
            audit_sink=InMemoryAuditSink(),
            masker=FieldMasker(),
        )
    app.state.gateway = gateway

    # --------------------------------------------------------------
    @app.exception_handler(GatewayError)
    async def _on_gateway_error(_: Request, exc: GatewayError) -> JSONResponse:
        # 统一错误信封：只含 code / message / reason，无敏感数据
        status = 403
        if isinstance(exc, MaskingError):
            status = 422
        elif isinstance(exc, AuditError):
            status = 503
        elif isinstance(exc, PolicyError):
            status = 409
        return JSONResponse(
            status_code=status,
            content={"error": {"code": exc.code, "reason": exc.reason}},
        )

    @app.exception_handler(KeyError)
    async def _on_missing_field(_: Request, exc: KeyError) -> JSONResponse:
        # 只回缺失字段名，不回请求体内容
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "bad_request",
                               "reason": f"missing_field:{exc.args[0]}"}},
        )

    @app.exception_handler(ValueError)
    async def _on_invalid_value(_: Request, exc: ValueError) -> JSONResponse:
        # 非法日期/枚举等：不回显输入值
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "bad_request", "reason": "invalid_value"}},
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/access")
    async def access(payload: dict) -> dict:
        subject = _parse_subject(payload["subject"])
        record = _parse_record(payload["record"])
        purpose = AccessPurpose(payload["purpose"])
        today = date.fromisoformat(payload["today"]) if payload.get("today") else None

        response = gateway.access(subject, record, purpose, today=today)
        ev = response.decision.evidence
        return {
            "decision": response.decision.decision.value,
            "audit_id": response.audit_id,
            "view": response.decision.view_name,
            "evidence": {
                "policy_version": ev.policy_version,
                "matched_rule_id": ev.matched_rule_id,
                "checks": {
                    "role": ev.role_ok,
                    "attributes": ev.attributes_ok,
                    "purpose": ev.purpose_ok,
                    "sensitivity": ev.sensitivity_ok,
                    "retention": ev.retention_ok,
                },
                "record_age_days": ev.record_age_days,
                "retention_days": ev.retention_days,
                "reasons": list(ev.reasons),
            },
            "fields": [
                {"name": f.name, "mode": f.mode, "value": f.value}
                for f in response.fields
            ],
        }

    @app.post("/v1/policies")
    async def publish_policy(payload: dict) -> dict:
        policy = _parse_policy(payload)
        gateway._store.publish(policy)  # noqa: SLF001 - 本地管理接口
        return {"published_version": policy.version}

    return app


# ----------------------------------------------------------------------
def _parse_subject(raw: dict) -> Subject:
    return Subject(
        subject_id=raw["subject_id"],
        roles=frozenset(raw["roles"]),
        attributes=frozenset(tuple(kv) for kv in raw.get("attributes", [])),
    )


def _parse_record(raw: dict) -> DataRecord:
    tags = {
        name: frozenset(t) for name, t in raw.get("field_tags", {}).items()
    }
    return DataRecord(
        record_id=raw["record_id"],
        resource_type=raw["resource_type"],
        collected_on=date.fromisoformat(raw["collected_on"]),
        fields=dict(raw["fields"]),
        field_levels={
            name: SensitivityLevel(level)
            for name, level in raw["field_levels"].items()
        },
        field_tags=tags,
    )


def _parse_policy(raw: dict) -> Policy:
    rules = tuple(
        AccessRule(
            rule_id=r["rule_id"],
            roles=frozenset(r["roles"]),
            allowed_purposes=frozenset(AccessPurpose(p) for p in r["allowed_purposes"]),
            max_sensitivity=SensitivityLevel(r["max_sensitivity"]),
            required_attributes=frozenset(
                tuple(kv) for kv in r.get("required_attributes", [])
            ),
            field_view=r["field_view"],
        )
        for r in raw["rules"]
    )
    views = {
        name: FieldView(
            name=name,
            visible_fields=frozenset(v["visible_fields"]),
            masked_fields=frozenset(v.get("masked_fields", [])),
            tokenized_fields=frozenset(v.get("tokenized_fields", [])),
        )
        for name, v in raw["views"].items()
    }
    retention = {
        rt: RetentionRule(
            resource_type=rt,
            retention_days=rr["retention_days"],
            expired_action=Decision(rr.get("expired_action", "audit_only")),
        )
        for rt, rr in raw.get("retention", {}).items()
    }
    return Policy(
        version=raw["version"],
        effective_from=date.fromisoformat(raw["effective_from"]),
        rules=rules,
        views=views,
        retention=retention,
    )
