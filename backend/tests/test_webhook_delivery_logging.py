from __future__ import annotations

from unittest.mock import MagicMock
from uuid import UUID

import httpx
from sqlmodel import Session

from backend.app.core.db import engine
from backend.app.services.webhook_service import deliver_case_payload


def test_webhook_delivery_logging(test_client):
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

    mock_http = MagicMock(spec=httpx.Client)
    mock_http.post.return_value = httpx.Response(status_code=200, text="ok")

    with Session(engine) as session:
        delivery = deliver_case_payload(
            session=session,
            case_id=case_id,
            webhook_url="http://example.com/webhook",
            client=mock_http,
        )

    assert delivery is not None
    assert delivery.delivered is True
    assert delivery.status_code == 200
    assert delivery.payload["schemaVersion"] == "case.v0.2"
    mock_http.post.assert_called_once()
