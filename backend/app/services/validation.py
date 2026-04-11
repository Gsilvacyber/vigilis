from __future__ import annotations

from typing import Any

from backend.app.schemas.case_v0_2 import CaseV0_2


def _has_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def validate_required_entities(case: CaseV0_2) -> None:
    """
    Enforce MVP required entities by alert type.
    Raises ValueError with a human-friendly message if required structure is missing.
    """

    required = []

    # Global MVP decisions
    actor = case.entities.actor
    identity = case.entities.identity
    if (
        not any(
            [
                _has_non_empty_string(identity.userId),
                _has_non_empty_string(identity.upn),
                _has_non_empty_string(identity.servicePrincipalId),
                _has_non_empty_string(identity.displayName),
            ]
        )
        and identity.identityType == "unknown"
    ):
        required.append("entities.identity")

    if not (
        _has_non_empty_string(actor.userId)
        or _has_non_empty_string(actor.upn)
        or _has_non_empty_string(actor.servicePrincipalId)
        or _has_non_empty_string(actor.displayName)
        or actor.identityType != "unknown"
    ):
        required.append("entities.actor")

    if required:
        raise ValueError(f"Missing required entities: {', '.join(required)}")

    alert_type = case.alertType

    def has_ips() -> bool:
        return len(case.entities.ips) > 0 and any(_has_non_empty_string(ip.ipAddress) for ip in case.entities.ips)

    def has_device() -> bool:
        d = case.entities.device
        return (
            _has_non_empty_string(d.deviceId)
            or _has_non_empty_string(d.hostname)
            or _has_non_empty_string(d.os)
            or d.identificationStatus != "unknown"
        )

    def has_app() -> bool:
        a = case.entities.app
        return _has_non_empty_string(a.appId) or _has_non_empty_string(a.name) or _has_non_empty_string(a.clientApp)

    def has_file() -> bool:
        f = case.entities.file
        return _has_non_empty_string(f.sha256) or _has_non_empty_string(f.fileName) or _has_non_empty_string(f.filePath)

    def has_mailbox() -> bool:
        m = case.entities.mailbox
        return (
            _has_non_empty_string(m.primaryAddress)
            or _has_non_empty_string(m.forwardingAddress)
            or _has_non_empty_string(m.ruleName)
        )

    def has_bulk_target() -> bool:
        bt = case.bulkTarget
        return (bt.count or 0) > 0 or len(bt.sampleTargets) > 0 or len(bt.succeededAccounts) > 0

    # Required entities by alert type (MVP)
    by_type: dict[str, list[str]] = {
        "identity.suspiciousSignIn": ["entities.identity", "entities.ips", "entities.device"],
        "identity.passwordSpray": ["entities.identity", "entities.ips", "bulkTarget"],
        "identity.mfaFatigue": ["entities.identity", "entities.ips"],
        "identity.oauthConsentRisk": ["entities.identity", "entities.app"],
        "identity.privilegeElevation": ["entities.identity", "entities.actor"],
        "endpoint.malwareDetection": ["entities.identity", "entities.device", "entities.file"],
        "endpoint.suspiciousProcess": ["entities.identity", "entities.device", "entities.file"],
        "email.forwardingRule": ["entities.identity", "entities.mailbox", "entities.ips"],
        "email.phishingDetected": ["entities.identity", "entities.ips"],
        "cloud.secretStoreAccessAnomaly": ["entities.identity", "entities.app"],
        "cloud.iamPrivilegeEscalation": ["entities.identity", "entities.app"],
        "cloud.suspiciousApiCall": ["entities.identity", "entities.app"],
        "network.impossibleGeoAccess": ["entities.identity", "entities.ips"],
        "network.dataExfiltration": ["entities.identity", "entities.ips"],
    }

    if alert_type not in by_type:
        raise ValueError(f"Unsupported alertType: {alert_type}")

    missing: list[str] = []
    for req in by_type[alert_type]:
        if req == "entities.ips" and not has_ips():
            missing.append(req)
        elif req == "entities.device" and not has_device():
            missing.append(req)
        elif req == "entities.app" and not has_app():
            missing.append(req)
        elif req == "entities.file" and not has_file():
            missing.append(req)
        elif req == "entities.mailbox" and not has_mailbox():
            missing.append(req)
        elif req == "bulkTarget" and not has_bulk_target():
            missing.append(req)
        elif req == "entities.actor":
            # Global actor requirement already checked; keep mapping consistent.
            if not (
                _has_non_empty_string(actor.userId)
                or _has_non_empty_string(actor.upn)
                or _has_non_empty_string(actor.servicePrincipalId)
                or _has_non_empty_string(actor.displayName)
                or actor.identityType != "unknown"
            ):
                missing.append(req)
        elif req == "entities.identity":
            if not (
                _has_non_empty_string(identity.userId)
                or _has_non_empty_string(identity.upn)
                or _has_non_empty_string(identity.servicePrincipalId)
                or _has_non_empty_string(identity.displayName)
                or identity.identityType != "unknown"
            ):
                missing.append(req)

    if missing:
        raise ValueError(f"Missing required entities for {alert_type}: {', '.join(missing)}")

