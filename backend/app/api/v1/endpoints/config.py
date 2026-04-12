"""Integration configuration endpoints - tenant-scoped."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.app.core.auth import require_tenant
from backend.app.services.config_service import (
    add_webhook_target,
    get_config,
    get_webhook_targets,
    update_config,
)

router = APIRouter(prefix="/config")


class WebhookTargetRequest(BaseModel):
    name: str
    url: str
    enabled: bool = True


class ConfigPatchRequest(BaseModel):
    mode: str | None = None
    disabledSignals: list[str] | None = None


@router.get("")
def api_get_config(auth_tenant: str = Depends(require_tenant)) -> dict[str, Any]:
    """Return integration configuration for the authenticated tenant."""
    return get_config(auth_tenant)


@router.patch("")
def api_patch_config(
    req: ConfigPatchRequest,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Update integration config for the authenticated tenant."""
    return update_config(auth_tenant, req.model_dump(exclude_none=True))


@router.get("/webhooks")
def api_get_webhooks(auth_tenant: str = Depends(require_tenant)) -> list[dict[str, Any]]:
    """List configured webhook targets for the authenticated tenant."""
    return get_webhook_targets(auth_tenant)


@router.post("/webhooks")
def api_add_webhook(
    req: WebhookTargetRequest,
    auth_tenant: str = Depends(require_tenant),
) -> list[dict[str, Any]]:
    """Add a webhook target for the authenticated tenant."""
    return add_webhook_target(auth_tenant, req.name, req.url, req.enabled)


@router.get("/signals-catalog")
def api_signals_catalog(
    auth_tenant: str = Depends(require_tenant),
) -> list[dict[str, Any]]:
    """Return the full signal catalog for UI denylist management.

    Excludes negative-weight suppression signals (noise_flag, ir_response,
    authorized_admin_activity, service_account_noise, blocked) because disabling
    those would INCREASE scores — nearly always not what the admin wants.
    Also excludes any signal name starting with `_` (internal markers like
    `_score_breakdown`).
    """
    from backend.app.services.enrichment.weights import SIGNAL_TIERS, W

    catalog: list[dict[str, Any]] = []
    for name in sorted(W.keys()):
        weight = W[name]
        if name.startswith("_"):
            continue
        if weight <= 0:
            continue
        catalog.append({
            "name": name,
            "weight": weight,
            "tier": SIGNAL_TIERS.get(name, "inferred"),
        })
    return catalog
