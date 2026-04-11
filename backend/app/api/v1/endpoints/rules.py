"""Suppression rule management endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session, select

from backend.app.core.auth import require_tenant
from backend.app.core.db import get_session
from backend.app.db.models import SuppressionRule
from backend.app.services.suppression_service import suggest_rules_from_dispositions, test_rule_conditions

router = APIRouter()


def db_session_dep() -> Session:
    return get_session()


class CreateRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = ""
    conditions: dict[str, Any] = {}
    action: str = "auto_close"
    actionValue: Optional[str] = None
    enabled: bool = True


class UpdateRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[dict[str, Any]] = None
    action: Optional[str] = None
    actionValue: Optional[str] = None
    enabled: Optional[bool] = None


def _rule_to_dict(r: SuppressionRule) -> dict[str, Any]:
    return {
        "id": r.id,
        "tenantId": r.tenant_id,
        "name": r.name,
        "description": r.description,
        "conditions": r.conditions,
        "action": r.action,
        "actionValue": r.action_value,
        "enabled": r.enabled,
        "hitsCount": r.hits_count,
        "createdAt": r.created_at.isoformat() if r.created_at else None,
        "updatedAt": r.updated_at.isoformat() if r.updated_at else None,
    }


@router.get("/rules")
def api_list_rules(
    auth_tenant: str = Depends(require_tenant),
) -> list[dict[str, Any]]:
    with db_session_dep() as session:
        rules = session.exec(
            select(SuppressionRule)
            .where(SuppressionRule.tenant_id == auth_tenant)
            .order_by(SuppressionRule.created_at.desc())
        ).all()
        return [_rule_to_dict(r) for r in rules]


@router.post("/rules")
def api_create_rule(
    req: CreateRuleRequest,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    with db_session_dep() as session:
        rule = SuppressionRule(
            tenant_id=auth_tenant,
            name=req.name,
            description=req.description,
            conditions=req.conditions,
            action=req.action,
            action_value=req.actionValue,
            enabled=req.enabled,
        )
        session.add(rule)
        session.commit()
        session.refresh(rule)
        return _rule_to_dict(rule)


class TestRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    conditions: dict[str, Any] = {}


@router.get("/rules/suggestions")
def api_rule_suggestions(
    auth_tenant: str = Depends(require_tenant),
    minCount: int = Query(3, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Suggest suppression rules based on benign disposition patterns."""
    with db_session_dep() as session:
        return suggest_rules_from_dispositions(session, auth_tenant, min_benign_count=minCount)


@router.post("/rules/test")
def api_test_rule(
    req: TestRuleRequest,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Test rule conditions against existing cases without creating a rule."""
    with db_session_dep() as session:
        return test_rule_conditions(session, auth_tenant, req.conditions)


@router.get("/rules/{rule_id}")
def api_get_rule(
    rule_id: int,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    with db_session_dep() as session:
        rule = session.exec(
            select(SuppressionRule)
            .where(SuppressionRule.id == rule_id)
            .where(SuppressionRule.tenant_id == auth_tenant)
        ).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        return _rule_to_dict(rule)


@router.patch("/rules/{rule_id}")
def api_update_rule(
    rule_id: int,
    req: UpdateRuleRequest,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    with db_session_dep() as session:
        rule = session.exec(
            select(SuppressionRule)
            .where(SuppressionRule.id == rule_id)
            .where(SuppressionRule.tenant_id == auth_tenant)
        ).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")

        if req.name is not None:
            rule.name = req.name
        if req.description is not None:
            rule.description = req.description
        if req.conditions is not None:
            rule.conditions = req.conditions
        if req.action is not None:
            rule.action = req.action
        if req.actionValue is not None:
            rule.action_value = req.actionValue
        if req.enabled is not None:
            rule.enabled = req.enabled
        rule.updated_at = datetime.now(timezone.utc)

        session.add(rule)
        session.commit()
        session.refresh(rule)
        return _rule_to_dict(rule)


@router.delete("/rules/{rule_id}")
def api_delete_rule(
    rule_id: int,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, str]:
    with db_session_dep() as session:
        rule = session.exec(
            select(SuppressionRule)
            .where(SuppressionRule.id == rule_id)
            .where(SuppressionRule.tenant_id == auth_tenant)
        ).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        session.delete(rule)
        session.commit()
        return {"status": "deleted"}


