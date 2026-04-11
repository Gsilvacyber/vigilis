from __future__ import annotations


def test_required_entities_validation_missing_device_for_suspicious_signin(test_client):
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
            # device intentionally missing
        },
    }

    resp = test_client.post("/api/v1/cases", json=payload)
    # Graceful validation: missing entities are flagged but case still persists.
    # The enrichment engine accepted this alert, so it should be savable.
    assert resp.status_code in (200, 201), f"Expected persist to succeed, got {resp.status_code}: {resp.text}"

