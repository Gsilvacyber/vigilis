from __future__ import annotations

from uuid import UUID

from sqlmodel import Session, select

from backend.app.db.models import Case as CaseRow


def test_case_creation_persists_and_returns_canonical(test_client, db_session: Session):
    payload = {
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

    resp = test_client.post("/api/v1/cases", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    assert data["schemaVersion"] == "case.v0.2"
    assert data["disposition"]["status"] == "open"
    assert data["entities"]["ips"] and data["entities"]["actor"]

    case_id = UUID(data["caseId"])

    db_session.expire_all()
    row = db_session.exec(select(CaseRow).where(CaseRow.id == case_id)).first()
    assert row is not None
    assert row.alert_type == "identity.suspiciousSignIn"
