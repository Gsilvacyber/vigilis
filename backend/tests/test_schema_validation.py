from __future__ import annotations


def test_schema_validation_invalid_severity(test_client):
    payload = {
        "tenantId": "tenant-1",
        "customer": {"name": "Cust", "environment": "prod", "industry": None},
        "alertType": "identity.suspiciousSignIn",
        "source": {
            "sourceSystem": "idp",
            "sourceName": "idp_mvp",
            "sourceAlertId": "alert-1",
            "sourceSeverity": "bogus",
            "sourceUrl": None,
        },
        "rawAlert": {},
    }

    resp = test_client.post("/api/v1/cases", json=payload)
    assert resp.status_code == 422

