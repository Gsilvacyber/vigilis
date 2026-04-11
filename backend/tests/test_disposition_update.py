from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlmodel import Session, select

from backend.app.db.models import Case as CaseRow, CaseDispositionEvent


def test_disposition_update_sets_ttfd(test_client, db_session: Session):
    create_payload = {
        "tenantId": "tenant-1",
        "customer": {"name": "Cust", "environment": "prod", "industry": None},
        "alertType": "identity.suspiciousSignIn",
        "source": {
            "sourceSystem": "idp",
            "sourceName": "idp_mvp",
            "sourceAlertId": "alert-1",
            "sourceSeverity": "medium",
            "sourceUrl": None,
        },
        "rawAlert": {
            "identity": {"identityType": "user", "userId": "u-1", "upn": "alice@example.com", "displayName": "Alice"},
            "actor": {"identityType": "user", "userId": "u-1", "upn": "alice@example.com", "displayName": "Alice"},
            "ips": [{"role": "anomalous", "ipAddress": "203.0.113.10"}],
            "device": {"deviceId": "d-1", "hostname": "ALICE-LAPTOP", "managed": True, "os": "Windows", "identificationStatus": "identified"},
        },
    }
    create_resp = test_client.post("/api/v1/cases", json=create_payload)
    assert create_resp.status_code == 200
    case_id = UUID(create_resp.json()["caseId"])

    set_at = datetime.now(timezone.utc)
    patch_payload = {
        "status": "investigating",
        "setBy": "analyst-1",
        "setAt": set_at.isoformat(),
        "notes": "Initial triage in progress",
    }
    patch_resp = test_client.patch(
        f"/api/v1/cases/{case_id}/disposition", json=patch_payload
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["disposition"]["status"] == "investigating"

    db_session.expire_all()

    row = db_session.exec(select(CaseRow).where(CaseRow.id == case_id)).first()
    assert row is not None
    assert row.time_to_first_decision_ms is not None
    assert row.time_to_first_decision_ms >= 0

    event = db_session.exec(
        select(CaseDispositionEvent).where(CaseDispositionEvent.case_id == case_id)
    ).first()
    assert event is not None
    assert event.ttfd_ms is not None
    assert event.status == "investigating"
