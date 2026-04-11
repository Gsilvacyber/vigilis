from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.app.services.enrichment.weights import W
from backend.app.services.enrichment.base import (
    Signal,
    get_action_status_weight,
    get_ip_countries,
    has_ad_attack_context,
    has_anomalous_ip,
    has_c2_beaconing_context,
    has_container_escape_context,
    has_data_exfil_context,
    has_domain_admin_context,
    has_domain_admin_context_tiered,
    has_dormant_account_context,
    has_external_ip,
    has_insider_threat_context,
    has_iot_ot_context,
    has_lateral_movement_context,
    has_persistence_context,
    has_ransomware_context,
    is_after_hours,
    is_ir_response,
    is_privileged_identity,
    is_service_account,
    multi_country_ips,
)


# ---------------------------------------------------------------------------
# identity.suspiciousSignIn
# ---------------------------------------------------------------------------

def extract_suspicious_sign_in(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    device = raw.get("device") or {}
    identity = raw.get("identity") or {}
    countries = get_ip_countries(raw)
    _is_svc = is_service_account(raw)
    _org_tz = raw.get("_orgTimezone") or None
    return [
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Sign-in from external anomalous IP address"),
        Signal("impossible_travel", W["impossible_travel"], multi_country_ips(raw),
               f"Impossible travel detected ({', '.join(countries)})" if countries else "Possible impossible travel detected"),
        Signal("unmanaged_device", W["unmanaged_device"], device.get("managed") is False and not _is_svc,
               "Sign-in from unmanaged device"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Privileged or admin account targeted"),
        Signal("mfa_concern", W["mfa_concern"],
               identity.get("mfaStatus") in ("disabled", "not_registered"),
               "MFA not satisfied or not registered"),
        Signal("high_risk_identity", W["high_risk_identity"],
               identity.get("riskLevel") in ("high", "critical"),
               "Identity flagged as high risk"),
        Signal("service_account_noise", W["service_account_noise"], _is_svc and not has_anomalous_ip(raw),
               "Service account with internal IP — likely routine"),
        Signal("external_geo", W["external_geo"],
               len(countries) == 1 and countries[0] not in ("United States", ""),
               f"Sign-in from {countries[0]}" if countries else "Sign-in from external geo"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status contributes to scoring"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Context indicates insider threat indicators"),
        Signal("resignation_on_file", W["resignation_on_file"], raw.get("_insiderResignation") is True,
               "User has resignation on file — heightened exfiltration risk"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Sign-in occurred outside business hours (10pm-6am)"),
        Signal("non_compliant_device", W["non_compliant_device"], raw.get("_deviceCompliant") is False,
               "Sign-in from non-compliant device"),
        Signal("credential_submission", W["credential_submission"], bool(raw.get("_credentialSubmission")),
               f"Credentials submitted externally ({raw.get('_credentialSubmission','')})"),
        Signal("source_high_risk", W["source_high_risk"], (raw.get("_sourceRiskScore") or 0) >= 80,
               f"Source system risk score: {raw.get('_sourceRiskScore',0)}"),
        Signal("concurrent_sessions", W["concurrent_sessions"], bool(raw.get("_sessionIPs")),
               "Concurrent sessions detected — possible account compromise"),
        Signal("impossible_travel_distance", W["impossible_travel_distance"],
               (raw.get("_distanceKm") or 0) > 1000,
               f"Impossible travel: {raw.get('_distanceKm',0)}km between sessions"),
        Signal("account_takeover_context", W["account_takeover_context"], _has_account_takeover_context(raw),
               "Account takeover indicators — MFA change, session hijack, or lockout"),
        Signal("noise_flag", W["noise_flag"], raw.get("_isNoise") is True,
               "Source flagged as noise — baseline activity"),
        Signal("ir_response", W["ir_response"], is_ir_response(raw),
               "Defensive/IR response action — not a threat"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack technique detected"),
        Signal("dormant_account", W["dormant_account"], has_dormant_account_context(raw),
               f"Dormant account activated ({raw.get('_passwordAgeDays',0)} days since password change)"),
        Signal("domain_admin_target", W["domain_admin_target"], has_domain_admin_context(raw),
               "Domain Admin or enterprise-level compromise indicators",
               tier=has_domain_admin_context_tiered(raw)[1] if has_domain_admin_context(raw) else "inferred"),
        Signal("container_escape", W["container_escape"], has_container_escape_context(raw),
               "Container escape or Kubernetes cluster compromise"),
        Signal("ransomware_chain", W["ransomware_chain"], has_ransomware_context(raw),
               "Ransomware attack chain — credential theft or lateral movement"),
        # Phase 4 additions — C2 and lateral movement in sign-in context
        Signal("c2_beaconing", W["c2_beaconing"], has_c2_beaconing_context(raw),
               "C2 beaconing indicators in sign-in context"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement indicators — multi-host compromise"),
    ]


# ---------------------------------------------------------------------------
# identity.passwordSpray
# ---------------------------------------------------------------------------

def extract_password_spray(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    bt = raw.get("bulkTarget") or {}
    identity = raw.get("identity") or {}
    countries = get_ip_countries(raw)
    _org_tz = raw.get("_orgTimezone") or None
    return [
        Signal("high_target_count", W["high_target_count"],
               (bt.get("count") or 0) > 10,
               "Large number of accounts targeted"),
        Signal("successful_login", W["successful_login"],
               (bt.get("successCount") or 0) > 0,
               "Successful authentication after spray — active breach"),
        Signal("anomalous_source_ip", W["anomalous_source_ip"], has_anomalous_ip(raw),
               "Attack originated from external anomalous IP"),
        Signal("foreign_origin", W["foreign_origin"],
               len(countries) >= 1 and countries[0] not in ("United States", ""),
               f"Attack originated from {countries[0]}" if countries else "Foreign attack origin"),
        Signal("privileged_target", W["privileged_target"], is_privileged_identity(raw),
               "Privileged account among targets"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Attack occurred outside business hours"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory credential attack (Kerberoasting, DCSync, or Pass-the-Hash)"),
        Signal("domain_admin_target", W["domain_admin_target"], has_domain_admin_context(raw),
               "Domain Admin compromise — full domain access at risk",
               tier=has_domain_admin_context_tiered(raw)[1] if has_domain_admin_context(raw) else "inferred"),
        Signal("dormant_account", W["dormant_account"], has_dormant_account_context(raw),
               "Dormant account credentials used — likely cracked offline"),
    ]


# ---------------------------------------------------------------------------
# identity.mfaFatigue
# ---------------------------------------------------------------------------

def extract_mfa_fatigue(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    identity = raw.get("identity") or {}
    mfa_prompts = raw.get("mfaPrompts") or {}
    _org_tz = raw.get("_orgTimezone") or None
    return [
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "MFA prompts triggered from external anomalous IP"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Privileged account targeted for MFA fatigue"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "MFA fatigue attempt outside business hours"),
        Signal("mfa_vulnerability", W["mfa_vulnerability"],
               identity.get("mfaStatus") in ("disabled", "not_registered"),
               "MFA status indicates vulnerability"),
        Signal("eventual_mfa_success", W["eventual_mfa_success"],
               bool(mfa_prompts.get("eventualSuccess")),
               "MFA was eventually accepted after repeated denials"),
        Signal("mfa_fatigue_context", W["mfa_fatigue_context"], _has_mfa_fatigue_context(raw),
               "Context confirms MFA fatigue attack — multiple push denials or rapid attempts"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Insider threat indicators in MFA fatigue context"),
    ]


def _has_account_takeover_context(raw: dict[str, Any]) -> bool:
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{ctx} {alert_name}"
    return any(kw in combined for kw in [
        "mfa phone", "phone number changed", "mfa changed",
        "attacker session", "attacker-controlled",
        "session hijack", "account lockout", "locked out",
        "password reset fail", "unrecognized device",
        "account takeover", "full control",
    ])


def _has_mfa_fatigue_context(raw: dict[str, Any]) -> bool:
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{ctx} {alert_name}"
    return any(kw in combined for kw in [
        "push denial", "push denied", "repeated denial",
        "fatigue", "rapid", "consecutive", "burst",
        "multiple push", "mfa bomb",
    ])


# ---------------------------------------------------------------------------
# identity.oauthConsentRisk
# ---------------------------------------------------------------------------

_RISKY_SCOPES = {
    "Mail.ReadWrite", "Mail.ReadWrite.All",
    "Files.ReadWrite.All", "Directory.ReadWrite.All",
    "User.ReadWrite.All", "Sites.ReadWrite.All",
}


def _is_admin_consent(raw: dict[str, Any]) -> bool:
    """Check if admin consent was granted to an application (tenant-wide access)."""
    ctx = (raw.get("_additionalContext") or "").lower()
    app = raw.get("app") or {}
    consent_type = (app.get("consentType") or "").lower()
    return "admin consent" in ctx or consent_type == "admin"


def _has_full_access_scopes(app: dict[str, Any]) -> bool:
    """Check if app has 3+ risky scopes — indicates broad read/write access."""
    scopes = set(app.get("scopes") or [])
    return len(scopes & _RISKY_SCOPES) >= 3

_KNOWN_PUBLISHERS = {"Microsoft", "Google", "Okta", "Auth0", "OneLogin"}


def extract_oauth_consent_risk(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    app = raw.get("app") or {}
    scopes = set(app.get("scopes") or [])
    publisher = (app.get("publisher") or "").strip()
    has_offline = "offline_access" in scopes
    return [
        Signal("broad_scopes", W["broad_scopes"],
               len(scopes) > 3 or bool(scopes & _RISKY_SCOPES),
               "Application requests broad or risky permission scopes"),
        Signal("offline_access", W["offline_access"], has_offline,
               "Token persists indefinitely via offline_access — survives password resets"),
        Signal("unknown_publisher", W["unknown_publisher"],
               not publisher or publisher not in _KNOWN_PUBLISHERS,
               "Application publisher is not recognized"),
        Signal("first_seen_app", W["first_seen_app"],
               app.get("firstSeenInTenantAt") is None,
               "Application not previously seen in tenant"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Consent granted by privileged user"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Insider threat context — may be establishing post-termination access"),
        Signal("resignation_on_file", W["resignation_on_file"], raw.get("_insiderResignation") is True,
               "User has resignation on file — OAuth token as persistence mechanism"),
        Signal("persistence", W["persistence"], has_persistence_context(raw),
               "Persistence mechanism detected via OAuth app"),
        # Phase 5 additions — raise OAuth mapper ceiling for dangerous patterns
        Signal("admin_consent_grant", W["admin_consent_grant"], _is_admin_consent(raw),
               "Admin consent granted to unknown application — tenant-wide access"),
        Signal("full_access_scopes", W["full_access_scopes"], _has_full_access_scopes(app),
               "Application has full read/write access to mail, files, and directory"),
    ]


# ---------------------------------------------------------------------------
# identity.privilegeElevation
# ---------------------------------------------------------------------------

def _actor_identity_mismatch(raw: dict[str, Any]) -> bool:
    identity = raw.get("identity") or {}
    actor = raw.get("actor") or {}
    id_key = (identity.get("userId") or identity.get("upn")
              or identity.get("servicePrincipalId") or "")
    act_key = (actor.get("userId") or actor.get("upn")
               or actor.get("servicePrincipalId") or "")
    if not id_key or not act_key:
        return False
    return id_key != act_key


def extract_privilege_elevation(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    identity = raw.get("identity") or {}
    actor = raw.get("actor") or {}
    _org_tz = raw.get("_orgTimezone") or None
    return [
        Signal("actor_identity_mismatch", W["actor_identity_mismatch"], _actor_identity_mismatch(raw),
               "Actor differs from target identity"),
        Signal("admin_role_grant", W["admin_role_grant"],
               identity.get("newPrivilegeTier") == "admin",
               "Admin-level role was granted"),
        Signal("privilege_level_admin", W["privilege_level_admin"],
               identity.get("privilegeTier") == "admin",
               "Account has admin privilege level"),
        Signal("already_privileged", W["already_privileged"], is_privileged_identity(raw),
               "Target is already a privileged account"),
        Signal("external_ip", W["external_ip"], has_external_ip(raw),
               "Activity from external IP address"),
        Signal("service_principal_actor", W["service_principal_actor"],
               actor.get("identityType") == "service_principal",
               "Change performed by service principal"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Privilege change occurred outside business hours"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Privilege change from external anomalous IP"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Context indicates insider threat — resignation, unauthorized change, or no change ticket"),
        Signal("persistence_mechanism", W["persistence_mechanism"], has_persistence_context(raw),
               "Persistence mechanism detected — survives account termination"),
        Signal("resignation_on_file", W["resignation_on_file"], raw.get("_insiderResignation") is True,
               "User has resignation on file — critical insider threat indicator"),
        Signal("no_change_ticket", W["no_change_ticket"], raw.get("_hasChangeTicket") is False,
               "No change ticket found — unauthorized privilege change"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack technique detected in context"),
        Signal("domain_admin_target", W["domain_admin_target"], has_domain_admin_context(raw),
               "Domain Admin level compromise indicators",
               tier=has_domain_admin_context_tiered(raw)[1] if has_domain_admin_context(raw) else "inferred"),
        Signal("container_escape", W["container_escape"], has_container_escape_context(raw),
               "Container escape or Kubernetes cluster compromise"),
        Signal("cve_exploited", W["cve_exploited"], raw.get("_cveExploited") is True,
               "Known CVE exploited — device compromised via unpatched vulnerability"),
        Signal("iot_ot_attack", W["iot_ot_attack"], has_iot_ot_context(raw),
               "IoT/OT/ICS attack — industrial device exploitation"),
    ]


# ---------------------------------------------------------------------------
# identity.impossibleTravel
# ---------------------------------------------------------------------------

def extract_impossible_travel(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    countries = get_ip_countries(raw)
    _org_tz = raw.get("_orgTimezone") or None
    _is_svc = is_service_account(raw)
    identity = raw.get("identity") or {}
    return [
        Signal("impossible_travel", W["impossible_travel"], multi_country_ips(raw),
               f"Impossible travel detected ({', '.join(countries)})" if countries else "Possible impossible travel detected"),
        Signal("impossible_travel_distance", W["impossible_travel_distance"],
               (raw.get("_distanceKm") or 0) > 500,
               f"Travel distance: {raw.get('_distanceKm', 0)}km between sessions"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Sign-in from external anomalous IP during travel anomaly"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Privileged account with impossible travel — high-value target"),
        Signal("concurrent_sessions", W["concurrent_sessions"], bool(raw.get("_sessionIPs")),
               "Concurrent active sessions from conflicting locations"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Impossible travel detected outside business hours"),
        Signal("external_geo", W["external_geo"],
               len(countries) == 1 and countries[0] not in ("United States", ""),
               f"Sign-in from {countries[0]}" if countries else "Sign-in from external geo"),
        Signal("high_risk_identity", W["high_risk_identity"],
               identity.get("riskLevel") in ("high", "critical"),
               "Identity flagged as high risk during travel anomaly"),
        Signal("account_takeover_context", W["account_takeover_context"], _has_account_takeover_context(raw),
               "Account takeover indicators alongside impossible travel"),
        Signal("service_account_noise", W["service_account_noise"], _is_svc and not has_anomalous_ip(raw),
               "Service account with internal IP — likely routine replication"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement indicators from impossible travel source"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack technique detected alongside travel anomaly"),
    ]


# ---------------------------------------------------------------------------
# identity.dormantAccountLogin
# ---------------------------------------------------------------------------

def extract_dormant_account_login(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    identity = raw.get("identity") or {}
    _org_tz = raw.get("_orgTimezone") or None
    pwd_age = raw.get("_passwordAgeDays") or 0
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("dormant_account", W["dormant_account"], has_dormant_account_context(raw),
               f"Dormant account activated ({pwd_age} days since password change)"),
        Signal("account_dormancy_days", W["account_dormancy_days"],
               pwd_age > 180,
               f"Account inactive for {pwd_age} days — exceeds 180-day threshold"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Dormant account accessed from anomalous IP"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Dormant privileged account reactivated — critical risk"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Dormant account login outside business hours"),
        Signal("service_account_interactive", W["service_account_interactive"],
               is_service_account(raw) and raw.get("_logonType") in ("interactive", "10"),
               "Dormant service account with interactive logon"),
        Signal("high_risk_identity", W["high_risk_identity"],
               identity.get("riskLevel") in ("high", "critical"),
               "Dormant account flagged as high risk"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status contributes to scoring"),
        Signal("persistence", W["persistence"], has_persistence_context(raw),
               "Persistence mechanism detected — dormant account as backdoor"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack using dormant credentials"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Insider threat indicators — dormant account may be ex-employee access"),
    ]


# ---------------------------------------------------------------------------
# identity.serviceAccountAbuse
# ---------------------------------------------------------------------------

def extract_service_account_abuse(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _org_tz = raw.get("_orgTimezone") or None
    _action_w, _action_desc = get_action_status_weight(raw)
    countries = get_ip_countries(raw)
    return [
        Signal("service_account_interactive", W["service_account_interactive"],
               is_service_account(raw) and raw.get("_logonType") in ("interactive", "10"),
               "Service account used for interactive logon — policy violation"),
        Signal("svc_unusual_host", W["svc_unusual_host"],
               bool(raw.get("_unusualSourceHost")),
               "Service account used from unusual host — not in baseline"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Service account accessed from anomalous IP"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Service account activity outside business hours"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Privileged service account — elevated blast radius"),
        Signal("impossible_travel", W["impossible_travel"], multi_country_ips(raw),
               f"Service account accessed from multiple countries ({', '.join(countries)})" if countries else "Multi-country service account access"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement using service account credentials"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack technique using service account"),
        Signal("no_change_ticket", W["no_change_ticket"], raw.get("_hasChangeTicket") is False,
               "No change ticket for service account activity"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status contributes to scoring"),
        Signal("persistence_mechanism", W["persistence_mechanism"], has_persistence_context(raw),
               "Service account used as persistence mechanism"),
        Signal("domain_admin_target", W["domain_admin_target"], has_domain_admin_context(raw),
               "Service account with domain admin level access",
               tier=has_domain_admin_context_tiered(raw)[1] if has_domain_admin_context(raw) else "inferred"),
    ]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

IDENTITY_EXTRACTORS = {
    "identity.suspiciousSignIn": extract_suspicious_sign_in,
    "identity.passwordSpray": extract_password_spray,
    "identity.mfaFatigue": extract_mfa_fatigue,
    "identity.oauthConsentRisk": extract_oauth_consent_risk,
    "identity.privilegeElevation": extract_privilege_elevation,
    "identity.impossibleTravel": extract_impossible_travel,
    "identity.dormantAccountLogin": extract_dormant_account_login,
    "identity.serviceAccountAbuse": extract_service_account_abuse,
}
