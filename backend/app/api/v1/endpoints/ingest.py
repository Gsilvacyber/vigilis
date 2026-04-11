from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.auth import require_tenant
from backend.app.core.db import get_session
from backend.app.schemas.case_v0_2 import Customer, Source
from backend.app.schemas.requests import CreateCaseRequest
from backend.app.services.alert_mapper import extract_event_time, map_row_to_raw_alert, parse_severity
from backend.app.services.case_service import create_case
from backend.app.services.incident_service import auto_correlate_background

_log = logging.getLogger(__name__)

# Map free-form product names to the SourceSystem literal enum
_SOURCE_SYSTEM_MAP: dict[str, str] = {
    # Identity providers
    "okta": "idp", "azuread": "idp", "azure_ad": "idp", "ping": "idp",
    "onelogin": "idp", "auth0": "idp", "duo": "idp",
    "microsoft sentinel": "idp", "sentinel": "idp",
    # EDR / Endpoint
    "crowdstrike": "edr", "falcon": "edr", "defender": "edr",
    "sentinelone": "edr", "carbon black": "edr", "cortex xdr": "edr",
    "cylance": "edr", "malwarebytes": "edr", "falco": "edr",
    # Email
    "proofpoint": "email", "mimecast": "email", "microsoft 365": "email",
    "exchange": "email", "barracuda": "email",
    # Cloud
    "aws guardduty": "cloud", "aws cloudtrail": "cloud", "aws config": "cloud",
    "azure": "cloud", "gcp": "cloud", "cloudflare": "cloud",
    # Network
    "cisco asa": "cloud", "palo alto": "network", "fortinet": "network",
    "snort": "network", "suricata": "network", "zeek": "network",
}
_VALID_SYSTEMS = {"idp", "edr", "email", "cloud", "network", "custom"}


def _normalize_source_system(raw: str) -> str:
    """Map free-form product/vendor name to SourceSystem literal."""
    lower = raw.lower().strip()
    if lower in _VALID_SYSTEMS:
        return lower
    return _SOURCE_SYSTEM_MAP.get(lower, "custom")


router = APIRouter(prefix="/ingest")


# ── Request / Response Models ────────────────────────────

class IngestAlertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sourceSystem: str
    sourceAlertId: str
    sourceSeverity: str = "medium"
    sourceUrl: Optional[str] = None
    alertType: Optional[str] = None
    eventTime: Optional[datetime] = None
    rawAlert: dict[str, Any]


class IngestBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alerts: list[IngestAlertRequest] = Field(..., max_length=100)


# ── Endpoints ────────────────────────────────────────────

@router.post("")
def api_ingest_alert(
    req: IngestAlertRequest,
    background_tasks: BackgroundTasks,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Accept a single alert from an external system (webhook push).

    Idempotent: sending the same sourceSystem + sourceAlertId twice
    returns the existing case instead of creating a duplicate.
    """
    if req.alertType:
        alert_type = req.alertType
        raw_alert = req.rawAlert
    else:
        alert_type, raw_alert = map_row_to_raw_alert(req.rawAlert)

    severity = req.sourceSeverity or parse_severity(req.rawAlert)
    event_time = req.eventTime or extract_event_time(req.rawAlert) or datetime.now(timezone.utc)

    with get_session() as session:
        try:
            create_req = CreateCaseRequest(
                tenantId=auth_tenant,
                customer=Customer(name="Webhook Ingest"),
                alertType=alert_type,
                source=Source(
                    sourceSystem=_normalize_source_system(req.sourceSystem),
                    sourceName=f"ingest:{req.sourceSystem}",
                    sourceAlertId=req.sourceAlertId,
                    sourceSeverity=severity,
                    sourceUrl=req.sourceUrl,
                ),
                rawAlert=raw_alert,
                severity=severity,
                eventTime=event_time,
            )
            case = create_case(session, create_req)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e

    background_tasks.add_task(auto_correlate_background, auth_tenant)

    return {
        "status": "ingested",
        "caseId": str(case.caseId),
        "alertType": alert_type,
        "confidence": case.confidence.score if case.confidence else None,
    }


@router.post("/batch")
def api_ingest_batch(
    req: IngestBatchRequest,
    background_tasks: BackgroundTasks,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Accept a batch of alerts (max 100). Enriches, deduplicates, creates cases."""
    created = 0
    errors = []
    case_ids = []

    for i, alert in enumerate(req.alerts):
        try:
            if alert.alertType:
                alert_type = alert.alertType
                raw_alert = alert.rawAlert
            else:
                alert_type, raw_alert = map_row_to_raw_alert(alert.rawAlert)

            severity = alert.sourceSeverity or parse_severity(alert.rawAlert)
            event_time = alert.eventTime or extract_event_time(alert.rawAlert) or datetime.now(timezone.utc)

            with get_session() as session:
                create_req = CreateCaseRequest(
                    tenantId=auth_tenant,
                    customer=Customer(name="Webhook Ingest"),
                    alertType=alert_type,
                    source=Source(
                        sourceSystem=alert.sourceSystem,
                        sourceName=f"ingest:{alert.sourceSystem}",
                        sourceAlertId=alert.sourceAlertId,
                        sourceSeverity=severity,
                        sourceUrl=alert.sourceUrl,
                    ),
                    rawAlert=raw_alert,
                    severity=severity,
                    eventTime=event_time,
                )
                case = create_case(session, create_req)
                case_ids.append(str(case.caseId))
                created += 1
        except Exception as e:
            errors.append({"index": i, "error": str(e)})

    background_tasks.add_task(auto_correlate_background, auth_tenant)

    return {
        "processed": len(req.alerts),
        "created": created,
        "errors": len(errors),
        "errorDetails": errors[:10],
        "caseIds": case_ids,
    }


@router.post("/pull")
def api_ingest_pull(
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Placeholder for future SIEM pull integration.

    Future implementation will poll SIEM APIs for new alerts and feed them
    through the same enrich/dedup/correlate pipeline.
    """
    raise HTTPException(
        status_code=501,
        detail={
            "message": "SIEM pull ingestion is not yet implemented",
            "planned": ["Microsoft Sentinel", "Splunk", "CrowdStrike Falcon", "Google SecOps/Chronicle"],
            "workaround": "Use POST /api/v1/ingest to push alerts via webhook, or POST /api/v1/demo/upload to upload files",
        },
    )
