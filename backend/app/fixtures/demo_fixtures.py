from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session

from backend.app.schemas.case_v0_2 import Customer, Source
from backend.app.schemas.requests import CreateCaseRequest
from backend.app.services.case_service import create_case

# ---------------------------------------------------------------------------
# Canonical sample raw alerts - one per supported alert type.
# Each includes enough risk indicators to trigger multiple enrichment signals.
# ---------------------------------------------------------------------------

SAMPLE_RAW_ALERTS: dict[str, dict[str, Any]] = {
    "identity.suspiciousSignIn": {
        "identity": {
            "identityType": "user",
            "userId": "u-123",
            "upn": "alice@contoso.com",
            "displayName": "Alice Contoso",
            "privilegeTier": "admin",
            "mfaStatus": "disabled",
            "riskLevel": "high",
        },
        "actor": {
            "identityType": "user",
            "userId": "u-123",
            "upn": "alice@contoso.com",
            "displayName": "Alice Contoso",
        },
        "ips": [
            {"role": "anomalous", "ipAddress": "203.0.113.10",
             "geo": {"country": "US", "city": "Seattle"}},
            {"role": "anomalous", "ipAddress": "198.51.100.5",
             "geo": {"country": "RU", "city": "Moscow"}},
        ],
        "device": {
            "deviceId": "d-unknown",
            "hostname": "UNKNOWN-PC",
            "managed": False,
            "os": "Linux",
            "identificationStatus": "unknown",
        },
    },
    "identity.passwordSpray": {
        "identity": {
            "identityType": "user",
            "userId": "u-999",
            "upn": "cfo@contoso.com",
            "displayName": "Chief Financial Officer",
            "privilegeTier": "admin",
        },
        "ips": [{"role": "anomalous", "ipAddress": "203.0.113.99"}],
        "bulkTarget": {
            "count": 250,
            "successCount": 3,
            "succeededAccounts": ["admin-svc", "cfo-user", "hr-admin"],
            "sampleTargets": [
                "admin@contoso.com", "cfo@contoso.com",
                "hr@contoso.com", "it-ops@contoso.com",
            ],
        },
    },
    "identity.mfaFatigue": {
        "identity": {
            "identityType": "user",
            "userId": "u-222",
            "upn": "dan@contoso.com",
            "displayName": "Dan Contoso",
            "privilegeTier": "privileged",
            "mfaStatus": "disabled",
        },
        "ips": [
            {"role": "anomalous", "ipAddress": "192.0.2.5",
             "geo": {"country": "CN", "city": "Shanghai"}},
        ],
    },
    "identity.oauthConsentRisk": {
        "identity": {
            "identityType": "user",
            "userId": "u-333",
            "upn": "erin@contoso.com",
            "displayName": "Erin Contoso",
            "privilegeTier": "admin",
        },
        "app": {
            "appId": "app-xyz",
            "name": "DocuHarvest Pro",
            "publisher": "UnknownDevCo",
            "scopes": [
                "Mail.ReadWrite", "Files.ReadWrite.All",
                "User.ReadWrite.All", "Directory.ReadWrite.All",
            ],
            "firstSeenInTenantAt": None,
        },
    },
    "identity.privilegeElevation": {
        "identity": {
            "identityType": "user",
            "userId": "u-123",
            "upn": "alice@contoso.com",
            "displayName": "Alice Contoso",
            "newPrivilegeTier": "admin",
        },
        "actor": {
            "identityType": "service_principal",
            "servicePrincipalId": "sp-attacker",
            "displayName": "Rogue Automation",
        },
        "ips": [{"role": "anomalous", "ipAddress": "203.0.113.10"}],
    },
    "endpoint.malwareDetection": {
        "identity": {
            "identityType": "user",
            "upn": "frank@contoso.com",
            "displayName": "Frank Contoso",
        },
        "device": {
            "deviceId": "d-2",
            "hostname": "FRANK-VM",
            "managed": True,
            "os": "Windows",
            "identificationStatus": "identified",
        },
        "file": {
            "fileName": "svchost-update.exe",
            "filePath": "C:\\Users\\Frank\\AppData\\Local\\Temp\\svchost-update.exe",
            "sha256": "7d2f4e8c1a9b3f5d" * 4,
            "signer": "Unknown",
            "prevalence": "rare",
        },
    },
    "endpoint.suspiciousProcess": {
        "identity": {
            "identityType": "user",
            "upn": "alice@contoso.com",
            "displayName": "Alice Contoso",
        },
        "device": {
            "deviceId": "d-3",
            "hostname": "ALICE-LAPTOP",
            "managed": True,
            "os": "Windows",
            "identificationStatus": "identified",
        },
        "file": {
            "fileName": "powershell.exe",
            "filePath": "C:\\Windows\\Temp\\staged\\powershell.exe",
            "sha256": "cafebabe" * 8,
            "signer": None,
        },
        "ips": [{"role": "anomalous", "ipAddress": "203.0.113.10"}],
    },
    "email.forwardingRule": {
        "identity": {
            "identityType": "user",
            "upn": "cfo@contoso.com",
            "displayName": "Chief Financial Officer",
            "privilegeTier": "admin",
        },
        "mailbox": {
            "primaryAddress": "cfo@contoso.com",
            "displayName": "CFO Mailbox",
            "ruleName": ".",
            "forwardingAddress": "collector@evil-domain.com",
        },
        "ips": [
            {"role": "anomalous", "ipAddress": "203.0.113.99",
             "geo": {"country": "NG", "city": "Lagos"}},
        ],
    },
    "cloud.secretStoreAccessAnomaly": {
        "identity": {
            "identityType": "user",
            "userId": "u-123",
            "upn": "alice@contoso.com",
            "displayName": "Alice Contoso",
        },
        "app": {
            "appId": "app-unknown",
            "name": "DataSync Pro",
            "publisher": "ShadowSoft LLC",
            "firstSeenInTenantAt": None,
        },
        "ips": [{"role": "anomalous", "ipAddress": "203.0.113.10"}],
    },
    "network.impossibleGeoAccess": {
        "identity": {
            "identityType": "user",
            "upn": "cfo@contoso.com",
            "displayName": "Chief Financial Officer",
            "privilegeTier": "admin",
        },
        "ips": [
            {"role": "anomalous", "ipAddress": "203.0.113.99",
             "geo": {"country": "FR", "city": "Paris"}},
            {"role": "anomalous", "ipAddress": "203.0.113.78",
             "geo": {"country": "JP", "city": "Tokyo"}},
        ],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SYSTEM_MAP: dict[str, str] = {
    "identity": "idp",
    "endpoint": "edr",
    "email": "email",
    "cloud": "cloud",
    "network": "network",
}


def _system_for(alert_type: str) -> str:
    return _SYSTEM_MAP.get(alert_type.split(".")[0], "custom")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Build / load demo cases
# ---------------------------------------------------------------------------

def build_demo_cases(tenant_id: str, customer: Customer) -> list[CreateCaseRequest]:
    now = _now()
    base = datetime(2026, 3, 26, 2, 0, 0, tzinfo=timezone.utc)

    _EVENT_TIMES: dict[str, datetime] = {
        # Chain 1 (alice): initial_access → priv_esc → execution → exfil
        "identity.suspiciousSignIn": base,
        "identity.privilegeElevation": base.replace(hour=2, minute=22),
        "endpoint.suspiciousProcess": base.replace(hour=2, minute=48),
        "cloud.secretStoreAccessAnomaly": base.replace(hour=3, minute=15),
        # Chain 2 (cfo): initial_access → credential_access → lateral_movement
        "email.forwardingRule": base.replace(hour=4, minute=0),
        "identity.passwordSpray": base.replace(hour=4, minute=35),
        "network.impossibleGeoAccess": base.replace(hour=5, minute=10),
    }

    # Realistic severity per alert type — attacks that bypass controls are high,
    # reconnaissance and policy violations are medium.
    _SEVERITY: dict[str, str] = {
        "identity.suspiciousSignIn": "high",
        "identity.privilegeElevation": "high",
        "endpoint.suspiciousProcess": "high",
        "endpoint.malwareDetection": "high",
        "cloud.secretStoreAccessAnomaly": "high",
        "email.forwardingRule": "medium",
        "identity.passwordSpray": "medium",
        "identity.mfaFatigue": "medium",
        "identity.oauthConsentRisk": "medium",
        "network.impossibleGeoAccess": "medium",
    }

    cases: list[CreateCaseRequest] = []
    for alert_type, raw in SAMPLE_RAW_ALERTS.items():
        sys = _system_for(alert_type)
        cases.append(
            CreateCaseRequest(
                tenantId=tenant_id,
                customer=customer,
                alertType=alert_type,
                source=Source(
                    sourceSystem=sys,
                    sourceName=f"{sys}_mvp",
                    sourceAlertId=f"{alert_type}:demo",
                    sourceSeverity=_SEVERITY.get(alert_type, "medium"),
                ),
                rawAlert=raw,
                eventTime=_EVENT_TIMES.get(alert_type, now),
            )
        )
    return cases


def load_demo_cases(session: Session, tenant_id: str, customer: Customer) -> int:
    requests = build_demo_cases(tenant_id=tenant_id, customer=customer)
    created = 0
    for r in requests:
        create_case(session, r)
        created += 1
    return created
