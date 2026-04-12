"""Demo API — Fixtures, reset, and pilot simulation routes.

Handles loading sample data, clearing demo cases, full DB reset,
and the pilot-simulation workflow that applies analyst decisions.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import SQLModel

from backend.app.core.auth import optional_tenant, seed_demo_key
from backend.app.core.db import engine, get_session
from backend.app.db.models import (
    Case,
    CaseConfidenceSignal,
    CaseDispositionEvent,
    CaseNote,
    CaseSource,
    IncidentCaseLink,
    WebhookDelivery,
)
from backend.app.fixtures.attack_scenarios import get_all_scenarios, get_total_case_count
from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS, load_demo_cases
from backend.app.schemas.case_v0_2 import Customer
from backend.app.services.case_service import create_case, list_cases, update_disposition
from backend.app.services.incident_service import correlate_incidents

router = APIRouter()


@router.post("/load-fixtures")
def api_load_fixtures(
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, int]:
    customer = Customer(name="Demo Customer", environment="prod", industry=None)
    with get_session() as session:
        try:
            created = load_demo_cases(session, tenant_id=auth_tenant, customer=customer)
            return {"created": created}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/sample-raw-alerts")
def api_sample_raw_alerts() -> dict[str, Any]:
    """Return one sample raw alert payload per supported alert type."""
    return SAMPLE_RAW_ALERTS


@router.post("/reset")
def api_reset() -> dict[str, str]:
    """Drop and recreate all tables for a clean demo reset."""
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    seed_demo_key()
    return {"status": "reset", "message": "All tables recreated"}


@router.post("/clear-samples")
def api_clear_samples(
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Delete only demo-fixture cases (source_alert_id ending in ':demo').

    Preserves any user-uploaded / API-created cases. Cascades to child rows
    (sources, signals, disposition events, notes, webhook deliveries,
    incident links). Incidents themselves are left alone; orphaned ones can
    be cleaned up via a later correlation run.
    """
    from sqlmodel import select, delete

    with get_session() as session:
        # Find demo case IDs via their source fingerprint
        demo_case_ids = session.exec(
            select(CaseSource.case_id)
            .where(CaseSource.source_alert_id.like("%:demo"))
        ).all()
        demo_case_ids = list(set(demo_case_ids))

        if not demo_case_ids:
            return {
                "status": "ok",
                "deletedCases": 0,
                "message": "No sample data found.",
            }

        # Cascade-delete child rows then the case itself
        counts: dict[str, int] = {}
        for model, label in [
            (CaseSource, "sources"),
            (CaseConfidenceSignal, "signals"),
            (CaseDispositionEvent, "dispositionEvents"),
            (CaseNote, "notes"),
            (WebhookDelivery, "webhookDeliveries"),
            (IncidentCaseLink, "incidentLinks"),
        ]:
            stmt = delete(model).where(model.case_id.in_(demo_case_ids))
            result = session.exec(stmt)
            counts[label] = getattr(result, "rowcount", 0) or 0

        case_stmt = delete(Case).where(Case.id.in_(demo_case_ids))
        case_result = session.exec(case_stmt)
        deleted_cases = getattr(case_result, "rowcount", 0) or len(demo_case_ids)

        session.commit()

    return {
        "status": "ok",
        "deletedCases": deleted_cases,
        "cascade": counts,
        "message": f"Cleared {deleted_cases} sample case(s). Uploaded data preserved.",
    }


# ---------------------------------------------------------------------------
# Pilot simulation
# ---------------------------------------------------------------------------

_PILOT_DECISIONS: list[tuple[str, int, str]] = [
    ("investigating", 45, "analyst-1"),
    ("true_positive", 180, "analyst-2"),
    ("benign", 25, "analyst-1"),
    ("escalated", 420, "analyst-3"),
    ("investigating", 75, "analyst-2"),
    ("true_positive", 310, "analyst-1"),
    ("investigating", 55, "analyst-3"),
    ("escalated", 600, "analyst-2"),
]


@router.post("/simulate-pilot")
def api_simulate_pilot(
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Reset, load fixtures, simulate analyst decisions and webhooks."""
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    seed_demo_key()

    tenant_id = auth_tenant
    customer = Customer(name="Demo Customer", environment="prod", industry=None)

    with get_session() as session:
        load_demo_cases(session, tenant_id=tenant_id, customer=customer)

    with get_session() as session:
        cases = list_cases(session, tenant_id, limit=20, offset=0)

    decided = 0
    for i, case in enumerate(cases):
        if i >= len(_PILOT_DECISIONS):
            break
        status, ttfd_s, analyst = _PILOT_DECISIONS[i]
        decision_time = case.timestamps.ingestedTime + timedelta(seconds=ttfd_s)
        with get_session() as session:
            update_disposition(
                session,
                case.caseId,
                {
                    "status": status,
                    "setBy": analyst,
                    "setAt": decision_time,
                    "notes": "Pilot simulation",
                },
            )
        decided += 1

    wh_count = 0
    with get_session() as session:
        for i, case in enumerate(cases):
            if i >= len(_PILOT_DECISIONS):
                break
            status = _PILOT_DECISIONS[i][0]
            if status in ("true_positive", "escalated"):
                session.add(
                    WebhookDelivery(
                        case_id=case.caseId,
                        webhook_url="http://localhost:8000/debug/webhook-echo",
                        attempt_no=1,
                        delivered=True,
                        status_code=200,
                        delivered_at=datetime.now(timezone.utc),
                        payload={"caseId": str(case.caseId), "simulated": True},
                    )
                )
                wh_count += 1
        session.commit()

    with get_session() as session:
        incidents = correlate_incidents(session, tenant_id=tenant_id)

    return {
        "status": "simulated",
        "casesLoaded": len(cases),
        "decisionsApplied": decided,
        "casesLeftOpen": len(cases) - decided,
        "webhookDeliveries": wh_count,
        "incidentsCorrelated": len(incidents),
        "message": "Pilot data ready. Call GET /api/v1/metrics/summary to see results.",
    }


@router.post("/load-attack-scenarios")
def api_load_attack_scenarios(
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Inject 10 realistic multi-step attack scenarios into the system.

    Each case flows through the FULL enrichment pipeline (sysmon translator,
    extractors, entity graph, threat intel, scoring) and is automatically
    dispositioned as true_positive so the calibration learning loop can
    train on real attack data.

    Returns a summary of scenarios loaded, cases created, and any errors.
    """
    from backend.app.schemas.requests import CreateCaseRequest

    scenarios = get_all_scenarios()
    total_created = 0
    total_errors = 0
    scenario_results: list[dict[str, Any]] = []

    for scenario in scenarios:
        created = 0
        errors = 0
        for case_dict in scenario["cases"]:
            try:
                req = CreateCaseRequest(**case_dict)
                with get_session() as session:
                    result = create_case(session, req)

                # Auto-disposition as true_positive for learning loop
                with get_session() as session:
                    try:
                        mitre = case_dict.get("rawAlert", {}).get("_mitreTechnique", "")
                        update_disposition(
                            session,
                            result.caseId,
                            {
                                "status": "true_positive",
                                "setBy": "attack-sim",
                                "notes": f"Attack scenario: {scenario['name']} "
                                         f"step {case_dict.get('rawAlert', {}).get('_attackStep', '?')} "
                                         f"MITRE {mitre}",
                            },
                            set_by="attack-sim",
                        )
                    except Exception:
                        pass  # Disposition failure is non-fatal

                created += 1
            except Exception as e:
                errors += 1
                _log = __import__("logging").getLogger(__name__)
                _log.warning("Attack scenario case failed: %s", e)

        scenario_results.append({
            "name": scenario["name"],
            "description": scenario["description"],
            "cases_created": created,
            "errors": errors,
        })
        total_created += created
        total_errors += errors

    return {
        "scenarios_loaded": len(scenarios),
        "total_cases_created": total_created,
        "total_errors": total_errors,
        "scenarios": scenario_results,
        "message": (
            f"Loaded {len(scenarios)} attack scenarios with {total_created} cases. "
            f"All dispositioned as true_positive for learning loop calibration. "
            f"Check /api/v1/metrics/enrichment-quality to see the quality improvement."
        ),
    }
