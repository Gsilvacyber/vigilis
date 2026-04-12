"""Exporter heartbeat endpoint — Days 1-3 observability.

Lets the 4 PowerShell exporters on the Windows VM (sysmon, psbl, secevt,
state) POST a lightweight heartbeat each run so the backend can detect
silent data loss within ~10 minutes if any exporter dies.

Storage design: reuses the existing AuditEvent table with
action="exporter_heartbeat" and exporter metadata in the `details` JSON
field. Zero schema migration, already tenant-isolated.

Staleness threshold: 600 seconds (10 minutes) — 2x the 5-min exporter
cadence. An exporter that misses one run shows `stale` on the status
endpoint.

Endpoints:
  POST /api/v1/exporter/heartbeat — exporter registers a run
  GET  /api/v1/exporter/status     — current state of all known exporters
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlmodel import select

from backend.app.core.auth import require_tenant
from backend.app.core.db import get_session
from backend.app.core.metrics import exporter_last_seen_seconds
from backend.app.db.models import AuditEvent

router = APIRouter()

# 10-minute freshness window — 2x the 5-min exporter cadence
FRESHNESS_WINDOW_SECONDS = 600


# ─── Schemas ──────────────────────────────────────────────────────────────

class ExporterHeartbeat(BaseModel):
    """Payload sent by PowerShell exporter at the end of each run."""
    exporter: str = Field(
        ...,
        description='Exporter name: "sysmon", "psbl", "secevt", or "state"',
    )
    hostname: str = Field(..., description="Source host (lowercased)")
    events_sent: int = Field(default=0, ge=0,
                             description="Events successfully POSTed this run")
    events_filtered: int = Field(default=0, ge=0,
                                 description="Events filtered/deduped this run")
    last_run: datetime = Field(..., description="ISO8601 UTC timestamp of the run")


# ─── POST /exporter/heartbeat ─────────────────────────────────────────────

@router.post("/exporter/heartbeat")
def post_heartbeat(
    body: ExporterHeartbeat,
    tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Record an exporter heartbeat.

    Writes an AuditEvent row and resets the `exporter_last_seen_seconds`
    Prometheus gauge to 0 for this (exporter, hostname) label pair.
    """
    exporter = body.exporter.strip().lower()
    hostname = body.hostname.strip().lower()

    with get_session() as session:
        audit = AuditEvent(
            tenant_id=tenant,
            actor=f"{exporter}@{hostname}",
            action="exporter_heartbeat",
            resource_type="exporter",
            resource_id=f"{exporter}@{hostname}",
            details={
                "exporter": exporter,
                "hostname": hostname,
                "events_sent": body.events_sent,
                "events_filtered": body.events_filtered,
                "last_run": body.last_run.isoformat(),
            },
        )
        session.add(audit)
        session.commit()

    # Reset the freshness gauge — this (exporter,hostname) just said hello
    exporter_last_seen_seconds.labels(
        exporter=exporter, hostname=hostname
    ).set(0)

    return {"status": "ok", "exporter": exporter, "hostname": hostname}


# ─── GET /exporter/status ─────────────────────────────────────────────────

@router.get("/exporter/status")
def get_exporter_status(
    tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Return the latest heartbeat per (exporter, hostname) pair.

    Queries AuditEvent rows with action="exporter_heartbeat" for this tenant,
    groups by (exporter, hostname), takes the most recent per group, and
    flags stale entries (last_seen > 10 minutes ago).
    """
    now = datetime.now(timezone.utc)
    # Look back 7 days to discover all exporters ever registered
    cutoff = now - timedelta(days=7)

    latest: dict[tuple[str, str], AuditEvent] = {}
    with get_session() as session:
        rows = session.exec(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant)
            .where(AuditEvent.action == "exporter_heartbeat")
            .where(AuditEvent.timestamp >= cutoff)
        ).all()

        for row in rows:
            details = row.details or {}
            exporter = str(details.get("exporter") or "").lower()
            hostname = str(details.get("hostname") or "").lower()
            if not exporter or not hostname:
                continue
            key = (exporter, hostname)
            prev = latest.get(key)
            if prev is None or row.timestamp > prev.timestamp:
                latest[key] = row

    exporters: list[dict[str, Any]] = []
    for (exporter, hostname), row in sorted(latest.items()):
        ts = row.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = int((now - ts).total_seconds())
        status = "fresh" if age < FRESHNESS_WINDOW_SECONDS else "stale"
        details = row.details or {}
        exporters.append({
            "exporter": exporter,
            "hostname": hostname,
            "last_seen": ts.isoformat(),
            "age_seconds": age,
            "status": status,
            "events_sent": int(details.get("events_sent") or 0),
            "events_filtered": int(details.get("events_filtered") or 0),
        })
        # Keep the Prometheus gauge in sync with wall-clock age
        exporter_last_seen_seconds.labels(
            exporter=exporter, hostname=hostname
        ).set(age)

    return {
        "tenant": tenant,
        "freshness_window_seconds": FRESHNESS_WINDOW_SECONDS,
        "exporters": exporters,
        "total": len(exporters),
        "fresh": sum(1 for e in exporters if e["status"] == "fresh"),
        "stale": sum(1 for e in exporters if e["status"] == "stale"),
    }
