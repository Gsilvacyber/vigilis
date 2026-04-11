from __future__ import annotations

from typing import Any, TYPE_CHECKING

from backend.app.services.enrichment.base import Signal

if TYPE_CHECKING:
    from backend.app.services.enrichment.cross_alert import CrossAlertSignal


# ── Stage-aware primary action mapping ────────────────────────────────────
# Maps kill-chain stages to the appropriate primary action label.
# Analysts get context-specific guidance based on WHERE in the attack
# chain this alert sits, not just what type of alert it is.
_STAGE_TO_ACTION: dict[str, str] = {
    "initial_access":       "INVESTIGATE",
    "credential_access":    "INVESTIGATE",
    "privilege_escalation": "ESCALATE",
    "execution":            "CONTAIN",
    "persistence":          "INVESTIGATE",
    "lateral_movement":     "CONTAIN",
    "collection":           "INVESTIGATE",
    "exfiltration":         "CONTAIN",
    "reconnaissance":       "INVESTIGATE",
}

_ALERT_TYPE_TO_STAGE: dict[str, str] = {
    "email.forwardingRule": "persistence",
    "email.phishingDetected": "initial_access",
    "identity.suspiciousSignIn": "initial_access",
    "identity.passwordSpray": "credential_access",
    "identity.mfaFatigue": "credential_access",
    "identity.oauthConsentRisk": "credential_access",
    "identity.privilegeElevation": "privilege_escalation",
    "endpoint.malwareDetection": "execution",
    "endpoint.suspiciousProcess": "execution",
    "endpoint.ransomwareDetection": "execution",
    "endpoint.lateralMovement": "lateral_movement",
    "endpoint.credentialDumping": "credential_access",
    "endpoint.persistenceMechanism": "persistence",
    "endpoint.defenseEvasion": "defense_evasion",
    "cloud.secretStoreAccessAnomaly": "exfiltration",
    "cloud.iamPrivilegeEscalation": "privilege_escalation",
    "cloud.suspiciousApiCall": "execution",
    "network.impossibleGeoAccess": "lateral_movement",
    "identity.impossibleTravel": "initial_access",
    "identity.dormantAccountLogin": "initial_access",
    "identity.serviceAccountAbuse": "credential_access",
    "email.businessEmailCompromise": "initial_access",
    "email.maliciousAttachment": "initial_access",
    "cloud.resourceHijacking": "execution",
    "cloud.dataExposure": "exfiltration",
    "network.commandAndControl": "lateral_movement",
    "network.portScan": "reconnaissance",
    "network.dnsAnomaly": "exfiltration",
    "network.dataExfiltration": "exfiltration",
    "dlp.sensitiveDataExposure": "collection",
}


def _fired_set(signals: list[Signal]) -> set[str]:
    return {s.name for s in signals if s.fired}


def _act(action: str, title: str, description: str,
         priority: str = "high", automated: bool = False) -> dict[str, Any]:
    return {"action": action, "title": title, "description": description,
            "priority": priority, "automated": automated}


# ---------------------------------------------------------------------------
# Per-alert-type action generators
# ---------------------------------------------------------------------------

def _suspicious_sign_in(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("review_sign_in_logs", "Review Sign-in Logs",
             "Investigate recent authentication events and session activity"),
        _act("validate_user", "Validate User Identity",
             "Contact the user to confirm the legitimacy of the sign-in"),
    ]
    if "anomalous_ip" in fired or "impossible_travel" in fired:
        actions.append(_act("block_source_ip", "Block Source IP",
                            "Block the anomalous IP at the network perimeter",
                            automated=True))
    if "unmanaged_device" in fired:
        actions.append(_act("enforce_device_compliance", "Enforce Device Compliance",
                            "Require device registration and compliance check",
                            priority="medium"))
    if "privileged_account" in fired:
        actions.append(_act("enhanced_monitoring", "Enable Enhanced Monitoring",
                            "Enable heightened logging and alerting for the privileged account",
                            automated=True))
    actions.append(_act("revoke_sessions", "Revoke Sessions if Confirmed",
                        "Terminate all active sessions and force re-authentication",
                        priority="critical"))
    return actions


def _password_spray(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("identify_targets", "Identify Targeted Accounts",
             "Enumerate all accounts included in the spray"),
        _act("review_auth_logs", "Review Authentication Logs",
             "Search for successful logins from the spray source"),
    ]
    if "successful_login" in fired:
        actions.append(_act("reset_passwords", "Reset Compromised Passwords",
                            "Force password reset for successfully sprayed accounts",
                            priority="critical"))
    if "anomalous_source_ip" in fired:
        actions.append(_act("block_source_ip", "Block Source IP",
                            "Block the attacking IP address at the perimeter",
                            automated=True))
    if "privileged_target" in fired:
        actions.append(_act("emergency_lockdown", "Emergency Account Lockdown",
                            "Lock privileged accounts that were targeted",
                            priority="critical"))
    actions.append(_act("enable_smart_lockout", "Enable Smart Lockout",
                        "Ensure account lockout policies are tuned to prevent sprays",
                        priority="medium", automated=True))
    return actions


def _mfa_fatigue(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("contact_user", "Contact User",
             "Verify with the user whether they initiated the MFA prompts",
             priority="critical"),
        _act("reset_mfa", "Reset MFA Registration",
             "Re-register MFA methods for the affected user"),
    ]
    if "anomalous_ip" in fired:
        actions.append(_act("investigate_sessions", "Investigate Session Theft",
                            "Check for active sessions that may result from an approved prompt"))
    if "privileged_account" in fired:
        actions.append(_act("revoke_sessions", "Revoke Active Sessions",
                            "Terminate all sessions for the privileged account",
                            priority="critical"))
    actions.append(_act("review_device_patterns", "Review Device Patterns",
                        "Validate device and location history for the user",
                        priority="medium"))
    return actions


def _oauth_consent_risk(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("revoke_consent", "Revoke Application Consent",
             "Remove the consent grant for the suspicious application",
             priority="critical"),
        _act("review_permissions", "Review Granted Permissions",
             "Audit the scopes and data access granted to the application"),
    ]
    if "broad_scopes" in fired:
        actions.append(_act("disable_app", "Disable Enterprise Application",
                            "Disable the application in the tenant to prevent further access",
                            priority="critical", automated=True))
    if "unknown_publisher" in fired:
        actions.append(_act("investigate_publisher", "Investigate Publisher",
                            "Research the application publisher for known threat activity"))
    actions.append(_act("notify_users", "Notify Affected Users",
                        "Inform users who may have been impacted by the application's access",
                        priority="medium"))
    return actions


def _privilege_elevation(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("validate_ticket", "Validate Change Ticket",
             "Confirm the role change against approved change management records"),
        _act("review_actor", "Review Actor History",
             "Investigate the actor's recent activity and authorization level"),
    ]
    if "actor_identity_mismatch" in fired:
        actions.append(_act("revert_role", "Revert Role Assignment",
                            "Roll back the privilege grant if the actor is not authorized",
                            priority="critical"))
    if "admin_role_grant" in fired:
        actions.append(_act("emergency_review", "Emergency Admin Review",
                            "Conduct immediate review of admin-level role grants",
                            priority="critical"))
    actions.append(_act("enable_monitoring", "Enable Enhanced Monitoring",
                        "Turn on heightened logging for the elevated account",
                        priority="medium", automated=True))
    return actions


def _malware_detection(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("isolate_host", "Isolate Host",
             "Network-isolate the affected endpoint immediately",
             priority="critical", automated=True),
        _act("quarantine_file", "Quarantine File",
             "Move the detected malware file to quarantine",
             priority="critical", automated=True),
    ]
    if "rare_file" in fired:
        actions.append(_act("submit_threat_intel", "Submit to Threat Intelligence",
                            "Upload the file hash for community threat intelligence lookup"))
    if "unsigned_binary" in fired:
        actions.append(_act("deep_analysis", "Deep File Analysis",
                            "Perform sandbox detonation and static analysis on the binary"))
    actions.append(_act("scan_related", "Scan Related Endpoints",
                        "Check other endpoints for the same indicators of compromise",
                        priority="medium"))
    return actions


def _suspicious_process(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("terminate_process", "Terminate Process",
             "Kill the suspicious process and child processes",
             priority="critical", automated=True),
        _act("isolate_host", "Isolate Host",
             "Network-isolate the affected endpoint",
             priority="critical", automated=True),
    ]
    if "powershell_usage" in fired or "known_lolbin" in fired:
        actions.append(_act("collect_forensics", "Collect Forensic Data",
                            "Capture process tree, command lines, and memory artifacts"))
    if "suspicious_path" in fired:
        actions.append(_act("check_persistence", "Check Persistence Mechanisms",
                            "Search for registry keys, scheduled tasks, or startup items"))
    actions.append(_act("review_process_chain", "Review Process Chain",
                        "Analyze parent-child process relationships",
                        priority="medium"))
    return actions


def _forwarding_rule(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("remove_rule", "Remove Forwarding Rule",
             "Delete the suspicious mail forwarding rule immediately",
             priority="critical", automated=True),
        _act("reset_credentials", "Reset Credentials",
             "Force password reset and revoke active sessions",
             priority="critical"),
    ]
    if "external_forward" in fired:
        actions.append(_act("audit_forwarded_email", "Audit Forwarded Emails",
                            "Review forwarded email content for data exposure assessment"))
    if "privileged_mailbox" in fired:
        actions.append(_act("executive_notification", "Executive Notification",
                            "Alert security leadership about the compromised executive mailbox"))
    actions.append(_act("enable_monitoring", "Enable Mailbox Monitoring",
                        "Turn on enhanced mailbox audit logging",
                        priority="medium", automated=True))
    return actions


def _secret_store_anomaly(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("review_access", "Review Access Logs",
             "Audit the secret store access timeline and accessed resources"),
        _act("rotate_secrets", "Rotate Exposed Secrets",
             "Rotate all secrets, keys, and certificates that may have been accessed",
             priority="critical"),
    ]
    if "service_principal_access" in fired:
        actions.append(_act("disable_token", "Disable Service Principal Token",
                            "Revoke tokens for the suspicious service principal",
                            priority="critical", automated=True))
    if "new_app" in fired:
        actions.append(_act("investigate_app", "Investigate Application",
                            "Research the application registration and its access history"))
    actions.append(_act("enable_logging", "Enable Enhanced Logging",
                        "Turn on detailed access logging for the secret store",
                        priority="medium", automated=True))
    return actions


def _impossible_geo(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("revoke_sessions", "Revoke Active Sessions",
             "Terminate sessions from the anomalous geographic location",
             priority="critical"),
        _act("validate_travel", "Validate Travel Records",
             "Check VPN usage and corporate travel records for the user"),
    ]
    if "anomalous_ip" in fired:
        actions.append(_act("block_ip", "Block Anomalous IP",
                            "Block the anomalous IP at the network perimeter",
                            automated=True))
    if "privileged_account" in fired:
        actions.append(_act("force_password_reset", "Force Password Reset",
                            "Require immediate password reset for the privileged account",
                            priority="critical"))
    actions.append(_act("conditional_access", "Apply Conditional Access",
                        "Implement location-based conditional access policies",
                        priority="medium", automated=True))
    return actions


def _iam_privilege_escalation(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("review_iam_changes", "Review IAM Changes",
             "Audit recent IAM role assignments and policy attachments for the identity",
             priority="critical"),
        _act("validate_change_ticket", "Validate Change Ticket",
             "Confirm the IAM change against approved change management records"),
    ]
    if "admin_role_grant" in fired:
        actions.append(_act("revert_role", "Revert Admin Role Assignment",
                            "Immediately remove the admin-level role grant if unauthorized",
                            priority="critical"))
    if "anomalous_ip" in fired:
        actions.append(_act("block_source_ip", "Block Source IP",
                            "Block the IP address that initiated the IAM change",
                            automated=True))
    if "no_change_ticket" in fired:
        actions.append(_act("escalate_to_iam_team", "Escalate to IAM Team",
                            "No change ticket found -- escalate for immediate IAM review",
                            priority="critical"))
    actions.append(_act("audit_escalated_actions", "Audit Escalated Actions",
                        "Review all API calls made under the escalated role in the last hour",
                        priority="medium"))
    return actions


def _suspicious_api_call(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("review_api_activity", "Review API Activity",
             "Audit recent API calls from the identity and compare against baseline"),
        _act("validate_caller_identity", "Validate Caller Identity",
             "Confirm the calling identity and its authorization for these API actions"),
    ]
    if "data_exfiltration_context" in fired:
        actions.append(_act("block_data_access", "Block Data Access",
                            "Restrict data-plane API access for the identity pending investigation",
                            priority="critical", automated=True))
    if "bulk_transfer" in fired:
        actions.append(_act("contain_data_transfer", "Contain Data Transfer",
                            "Halt bulk data operations and preserve transfer logs",
                            priority="critical"))
    if "anomalous_ip" in fired:
        actions.append(_act("block_source_ip", "Block Source IP",
                            "Block the anomalous source IP at the network perimeter",
                            automated=True))
    actions.append(_act("review_user_agent", "Review User Agent Strings",
                        "Check if API calls originated from expected tooling or attack frameworks",
                        priority="medium"))
    return actions


def _phishing_detected(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("block_sender", "Block Sender Domain",
             "Block the phishing sender domain at the email gateway",
             priority="critical", automated=True),
        _act("search_related_emails", "Search for Related Emails",
             "Find all emails from the same sender or with the same URL across the tenant"),
    ]
    if "external_forward" in fired:
        actions.append(_act("check_forwarding_rules", "Check Forwarding Rules",
                            "Verify no auto-forwarding rules were created after phishing interaction",
                            priority="critical"))
    if "privileged_mailbox" in fired:
        actions.append(_act("executive_protection", "Executive Account Protection",
                            "Reset credentials and revoke sessions for the targeted executive account",
                            priority="critical"))
    if "credential_harvest" in fired or "credential_theft" in fired:
        actions.append(_act("reset_credentials", "Reset Compromised Credentials",
                            "Force password reset for any user who submitted credentials to the phishing page",
                            priority="critical"))
    actions.append(_act("notify_recipients", "Notify Affected Recipients",
                        "Inform all recipients of the phishing campaign with guidance",
                        priority="medium"))
    return actions


def _data_exfiltration(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("block_destination", "Block Exfiltration Destination",
             "Block the external destination at the network perimeter",
             priority="critical", automated=True),
        _act("preserve_evidence", "Preserve Transfer Evidence",
             "Capture DLP logs, proxy logs, and file access audit records"),
    ]
    if "insider_data_exfil" in fired:
        actions.append(_act("hr_notification", "Notify HR and Legal",
                            "Insider threat indicators present -- coordinate with HR and legal teams",
                            priority="critical"))
    if "resignation_on_file" in fired:
        actions.append(_act("restrict_access", "Restrict Data Access",
                            "Reduce data access permissions for the departing employee",
                            priority="critical"))
    if "bulk_transfer" in fired:
        actions.append(_act("assess_data_impact", "Assess Data Impact",
                            "Determine classification and volume of transferred data",
                            priority="critical"))
    actions.append(_act("enable_dlp_monitoring", "Enable Enhanced DLP Monitoring",
                        "Turn on heightened data loss prevention monitoring for the user",
                        priority="medium", automated=True))
    return actions


def _impossible_travel(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("review_geo_timeline", "Review Geographic Timeline",
             "Map all authentication events by time and geographic location for the user"),
        _act("validate_travel", "Validate Travel Records",
             "Check VPN usage and corporate travel records to explain location change"),
    ]
    if "impossible_travel_distance" in fired:
        actions.append(_act("kill_newer_session", "Kill Newer Session",
                            "Terminate the more recent session — one location is the attacker",
                            priority="critical"))
    if "concurrent_sessions" in fired:
        actions.append(_act("revoke_all_sessions", "Revoke All Sessions",
                            "Terminate all active sessions and force re-authentication",
                            priority="critical"))
    if "privileged_account" in fired:
        actions.append(_act("force_password_reset", "Force Password Reset",
                            "Require immediate password reset for the privileged account",
                            priority="critical"))
    actions.append(_act("apply_conditional_access", "Apply Conditional Access",
                        "Implement location-based conditional access policies",
                        priority="medium", automated=True))
    return actions


def _dormant_account_login(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("verify_reactivation", "Verify Account Reactivation",
             "Confirm whether the dormant account was intentionally reactivated"),
        _act("review_auth_history", "Review Authentication History",
             "Check the full authentication timeline for the last 365 days"),
    ]
    if "account_dormancy_days" in fired:
        actions.append(_act("disable_account", "Disable Account",
                            "Disable the dormant account pending investigation",
                            priority="critical"))
    if "anomalous_ip" in fired:
        actions.append(_act("block_source_ip", "Block Source IP",
                            "Block the anomalous IP at the network perimeter",
                            automated=True))
    if "privileged_account" in fired:
        actions.append(_act("emergency_lockdown", "Emergency Account Lockdown",
                            "Lock the privileged dormant account immediately",
                            priority="critical"))
    actions.append(_act("credential_audit", "Credential Audit",
                        "Check if credentials appeared in known breaches",
                        priority="medium"))
    return actions


def _service_account_abuse(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("review_svc_usage", "Review Service Account Usage",
             "Compare current activity against the service account baseline"),
        _act("validate_source_host", "Validate Source Host",
             "Confirm whether the source host is in the known service host list"),
    ]
    if "service_account_interactive" in fired:
        actions.append(_act("disable_account", "Disable Service Account",
                            "Disable the service account — interactive logon is a policy violation",
                            priority="critical"))
    if "svc_unusual_host" in fired:
        actions.append(_act("isolate_host", "Isolate Source Host",
                            "Network-isolate the unusual host using the service account",
                            priority="critical", automated=True))
    if "lateral_movement" in fired:
        actions.append(_act("contain_lateral", "Contain Lateral Movement",
                            "Block service account from authenticating to additional hosts",
                            priority="critical"))
    actions.append(_act("audit_permissions", "Audit Service Account Permissions",
                        "Review all permissions — enforce principle of least privilege",
                        priority="medium"))
    return actions


def _business_email_compromise(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("alert_finance", "Alert Finance Team",
             "Notify finance to hold all pending wire transfers and payment requests",
             priority="critical"),
        _act("verify_sender", "Verify Sender Identity",
             "Compare sender email headers and domain against known legitimate correspondence"),
    ]
    if "wire_transfer_context" in fired:
        actions.append(_act("hold_transfers", "Hold Wire Transfers",
                            "Immediately halt all pending wire transfers from the targeted department",
                            priority="critical"))
    if "lookalike_domain" in fired:
        actions.append(_act("block_domain", "Block Lookalike Domain",
                            "Block the lookalike sender domain at the email gateway",
                            priority="critical", automated=True))
    if "targets_executive" in fired or "executive_impersonation" in fired:
        actions.append(_act("executive_notification", "Executive Notification",
                            "Alert security leadership about the BEC targeting executives"))
    actions.append(_act("search_campaign", "Search for Campaign",
                        "Search for similar BEC emails to other employees in the organization",
                        priority="medium"))
    return actions


def _malicious_attachment(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("quarantine_email", "Quarantine Email",
             "Remove the malicious email from all recipient inboxes",
             priority="critical", automated=True),
        _act("submit_to_sandbox", "Submit to Sandbox",
             "Submit the attachment hash to VirusTotal and sandbox for analysis"),
    ]
    if "malicious_attachment" in fired:
        actions.append(_act("search_hash", "Search for Attachment Hash",
                            "Find all emails with the same attachment hash across the organization",
                            priority="critical"))
    if "macro_enabled" in fired:
        actions.append(_act("check_execution", "Check Macro Execution",
                            "Look for child processes spawned from Office applications on recipient endpoints",
                            priority="critical"))
    if "ransomware_context" in fired:
        actions.append(_act("isolate_endpoints", "Isolate Recipient Endpoints",
                            "Network-isolate all endpoints where the attachment was opened",
                            priority="critical", automated=True))
    actions.append(_act("block_sender", "Block Sender Domain",
                        "Add the sender domain to the email gateway block list",
                        priority="medium", automated=True))
    return actions


def _ransomware_detection(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("isolate_host", "Isolate Host Immediately",
             "Network-isolate the affected endpoint to prevent ransomware spread",
             priority="critical", automated=True),
        _act("preserve_evidence", "Preserve Forensic Evidence",
             "Capture memory dump, process tree, and ransom note before remediation"),
    ]
    if "shadow_copy_deletion" in fired:
        actions.append(_act("check_backups", "Verify Backup Integrity",
                            "Shadow copies deleted — verify offline backups are intact and uncompromised",
                            priority="critical"))
    if "mass_file_encryption" in fired:
        actions.append(_act("assess_blast_radius", "Assess Encryption Blast Radius",
                            "Determine the scope of encrypted files and affected shares",
                            priority="critical"))
    if "lateral_movement" in fired:
        actions.append(_act("isolate_subnet", "Isolate Affected Subnet",
                            "Ransomware spreading laterally — isolate the entire subnet",
                            priority="critical", automated=True))
    actions.append(_act("identify_family", "Identify Ransomware Family",
                        "Determine ransomware variant from file extensions, ransom note, or IOCs",
                        priority="high"))
    return actions


def _lateral_movement_actions(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("block_source_host", "Block Source Host",
             "Block the source host from making further remote connections",
             priority="critical", automated=True),
        _act("review_credentials", "Review Source Credentials",
             "Investigate how the attacker obtained credentials used for lateral movement"),
    ]
    if "remote_service_abuse" in fired:
        actions.append(_act("disable_remote_services", "Disable Remote Services",
                            "Disable PsExec, WMI remote, and WinRM on non-admin workstations",
                            priority="critical"))
    if "multiple_devices_compromised" in fired:
        actions.append(_act("isolate_affected_hosts", "Isolate All Affected Hosts",
                            "Multiple hosts compromised — isolate all identified targets",
                            priority="critical", automated=True))
    if "ad_attack" in fired:
        actions.append(_act("ad_containment", "Active Directory Containment",
                            "Reset KRBTGT and review AD trust relationships",
                            priority="critical"))
    actions.append(_act("map_movement_path", "Map Movement Path",
                        "Document the full lateral movement chain: source -> pivot -> destination",
                        priority="high"))
    return actions


def _credential_dumping_actions(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("isolate_host", "Isolate Compromised Host",
             "Network-isolate the host where credential dumping occurred",
             priority="critical", automated=True),
        _act("reset_credentials", "Reset Compromised Credentials",
             "Force password reset for all accounts logged into the compromised host",
             priority="critical"),
    ]
    if "dc_target" in fired:
        actions.append(_act("reset_krbtgt", "Reset KRBTGT Account",
                            "Domain controller targeted — reset KRBTGT twice to invalidate golden tickets",
                            priority="critical"))
    if "known_attack_tool" in fired:
        actions.append(_act("hunt_tool_artifacts", "Hunt for Tool Artifacts",
                            "Search all endpoints for the same attack tool (mimikatz, rubeus, etc.)",
                            priority="critical"))
    if "domain_admin_context" in fired:
        actions.append(_act("domain_admin_lockdown", "Domain Admin Lockdown",
                            "Reset all domain admin passwords and review admin group membership",
                            priority="critical"))
    actions.append(_act("deploy_credential_guard", "Deploy Credential Guard",
                        "Enable Credential Guard and LSASS protection on affected endpoints",
                        priority="high"))
    return actions


def _persistence_mechanism_actions(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("disable_persistence", "Disable Persistence Mechanism",
             "Remove or disable the suspicious scheduled task, service, or registry key",
             priority="critical"),
        _act("collect_artifact", "Collect Persistence Artifact",
             "Preserve the persistence mechanism for forensic analysis before removal"),
    ]
    if "known_attack_tool" in fired:
        actions.append(_act("full_scan", "Full Endpoint Scan",
                            "Known attack tool established persistence — run full endpoint scan",
                            priority="critical", automated=True))
    if "server_target" in fired:
        actions.append(_act("server_audit", "Server Security Audit",
                            "Persistence on server — audit all scheduled tasks, services, and startup items",
                            priority="critical"))
    if "insider_persistence" in fired:
        actions.append(_act("hr_notification", "Notify HR and Legal",
                            "Insider persistence indicators — coordinate with HR and legal teams",
                            priority="critical"))
    actions.append(_act("baseline_comparison", "Compare Against Baseline",
                        "Verify persistence mechanism against known administrative baselines",
                        priority="medium"))
    return actions


def _defense_evasion_actions(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("restore_controls", "Restore Security Controls",
             "Re-enable any disabled AV, EDR, or logging mechanisms immediately",
             priority="critical", automated=True),
        _act("investigate_actor", "Investigate Disabling Actor",
             "Identify who or what process disabled security controls"),
    ]
    if "av_disabled" in fired:
        actions.append(_act("force_av_reenable", "Force AV Re-enable",
                            "Push AV/EDR re-enablement policy and verify tamper protection",
                            priority="critical", automated=True))
    if "log_cleared" in fired:
        actions.append(_act("recover_logs", "Recover Cleared Logs",
                            "Check centralized SIEM for copies of cleared event logs",
                            priority="critical"))
    if "defense_evasion_detected" in fired:
        actions.append(_act("hunt_injection", "Hunt for Process Injection",
                            "Search for AMSI bypass, ETW patching, and process injection across endpoints",
                            priority="critical"))
    actions.append(_act("validate_controls", "Validate Security Controls",
                        "Verify all security controls are operational across the environment",
                        priority="high"))
    return actions


def _resource_hijacking(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("terminate_mining", "Terminate Mining Processes",
             "Kill unauthorized crypto mining processes and related workloads",
             priority="critical", automated=True),
        _act("isolate_instance", "Isolate Compromised Instance",
             "Network-isolate the hijacked instance to prevent lateral spread"),
    ]
    if "container_escape" in fired:
        actions.append(_act("revoke_node_credentials", "Revoke Node Credentials",
                            "Rotate all credentials on the compromised node -- container escape confirmed",
                            priority="critical"))
    if "anomalous_ip" in fired:
        actions.append(_act("block_mining_pool", "Block Mining Pool IPs",
                            "Block outbound connections to mining pool infrastructure",
                            automated=True))
    actions.append(_act("audit_iam_keys", "Audit IAM Keys on Instance",
                        "Check for harvested cloud credentials on the compromised instance",
                        priority="medium"))
    return actions


def _cloud_data_exposure(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("remediate_access", "Remediate Public Access",
             "Remove public access from the exposed storage resource immediately",
             priority="critical", automated=True),
        _act("inventory_data", "Inventory Exposed Data",
             "Determine the classification and volume of data that was accessible"),
    ]
    if "classified_data" in fired:
        actions.append(_act("notify_compliance", "Notify Compliance Team",
                            "Classified data was exposed -- engage compliance for breach assessment",
                            priority="critical"))
    if "data_exfiltration_context" in fired:
        actions.append(_act("review_access_logs", "Review Access Logs",
                            "Check storage access logs for external downloads during exposure window",
                            priority="critical"))
    actions.append(_act("enable_guardrails", "Enable Preventive Guardrails",
                        "Deploy SCPs or organization policies to prevent future public storage",
                        priority="medium", automated=True))
    return actions


def _command_and_control(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("isolate_host", "Isolate Affected Host",
             "Network-isolate the host communicating with C2 infrastructure",
             priority="critical", automated=True),
        _act("block_c2_destination", "Block C2 Destination",
             "Block the C2 IP/domain at firewall and DNS resolver",
             priority="critical", automated=True),
    ]
    if "known_malicious_ip" in fired:
        actions.append(_act("threat_intel_sweep", "Threat Intel Sweep",
                            "Search all endpoints and proxy logs for connections to the known malicious IP"))
    if "dns_tunnel" in fired:
        actions.append(_act("block_dns_domain", "Block DNS Domain",
                            "Sinkhole the DNS domain used for tunneling at the resolver",
                            automated=True))
    actions.append(_act("collect_forensics", "Collect Forensic Artifacts",
                        "Capture memory dump, process tree, and network connections from affected host",
                        priority="medium"))
    return actions


def _port_scan(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("identify_scanner", "Identify Scanner Source",
             "Determine if the scanning host is internal (compromised) or external (attacker)"),
        _act("validate_authorization", "Validate Scan Authorization",
             "Check if a change ticket or vulnerability scan window covers this activity"),
    ]
    if "anomalous_ip" in fired:
        actions.append(_act("block_scanner_ip", "Block Scanner IP",
                            "Block the scanning IP at the network perimeter",
                            priority="critical", automated=True))
    if "port_scan_detected" in fired and "after_hours" in fired:
        actions.append(_act("investigate_host", "Investigate Source Host",
                            "After-hours scanning likely indicates compromised host -- investigate for malware",
                            priority="critical"))
    actions.append(_act("review_exposed_services", "Review Exposed Services",
                        "Audit services that responded to the scan for vulnerabilities",
                        priority="medium"))
    return actions


def _dns_anomaly(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("block_suspicious_domain", "Block Suspicious Domain",
             "Sinkhole the anomalous domain at the DNS resolver",
             priority="critical", automated=True),
        _act("isolate_source", "Isolate Source Host",
             "Network-isolate the host generating anomalous DNS queries"),
    ]
    if "dns_tunnel" in fired:
        actions.append(_act("analyze_query_payload", "Analyze Query Payloads",
                            "Decode DNS query subdomains to determine exfiltrated data content",
                            priority="critical"))
    if "bulk_transfer" in fired:
        actions.append(_act("assess_data_loss", "Assess Data Loss",
                            "Estimate volume and content of data exfiltrated via DNS channel",
                            priority="critical"))
    actions.append(_act("review_resolver_logs", "Review DNS Resolver Logs",
                        "Check for other clients querying the same suspicious domain",
                        priority="medium"))
    return actions


def _sensitive_data_exposure(signals: list[Signal]) -> list[dict[str, Any]]:
    fired = _fired_set(signals)
    actions = [
        _act("contain_data", "Contain Data Exposure",
             "Remove or restrict access to the sensitive data in the unauthorized location",
             priority="critical", automated=True),
        _act("assess_classification", "Assess Data Classification",
             "Determine the classification level and regulatory implications of exposed data"),
    ]
    if "insider_data_exfil" in fired:
        actions.append(_act("engage_hr_legal", "Engage HR and Legal",
                            "Insider threat indicators present -- coordinate with HR and legal teams",
                            priority="critical"))
    if "resignation_on_file" in fired:
        actions.append(_act("restrict_user_access", "Restrict User Access",
                            "Immediately reduce data access permissions for the departing employee",
                            priority="critical"))
    if "pii_detected" in fired:
        actions.append(_act("breach_notification", "Initiate Breach Notification",
                            "PII confirmed -- begin regulatory breach notification assessment",
                            priority="critical"))
    actions.append(_act("review_dlp_policies", "Review DLP Policies",
                        "Audit DLP policy coverage to close gaps that allowed this exposure",
                        priority="medium"))
    return actions


_ACTION_GENERATORS: dict[str, Any] = {
    "identity.suspiciousSignIn": _suspicious_sign_in,
    "identity.passwordSpray": _password_spray,
    "identity.mfaFatigue": _mfa_fatigue,
    "identity.oauthConsentRisk": _oauth_consent_risk,
    "identity.privilegeElevation": _privilege_elevation,
    "endpoint.malwareDetection": _malware_detection,
    "endpoint.suspiciousProcess": _suspicious_process,
    "email.forwardingRule": _forwarding_rule,
    "cloud.secretStoreAccessAnomaly": _secret_store_anomaly,
    "network.impossibleGeoAccess": _impossible_geo,
    "cloud.iamPrivilegeEscalation": _iam_privilege_escalation,
    "cloud.suspiciousApiCall": _suspicious_api_call,
    "email.phishingDetected": _phishing_detected,
    "network.dataExfiltration": _data_exfiltration,
    "identity.impossibleTravel": _impossible_travel,
    "identity.dormantAccountLogin": _dormant_account_login,
    "identity.serviceAccountAbuse": _service_account_abuse,
    "email.businessEmailCompromise": _business_email_compromise,
    "email.maliciousAttachment": _malicious_attachment,
    "endpoint.ransomwareDetection": _ransomware_detection,
    "endpoint.lateralMovement": _lateral_movement_actions,
    "endpoint.credentialDumping": _credential_dumping_actions,
    "endpoint.persistenceMechanism": _persistence_mechanism_actions,
    "endpoint.defenseEvasion": _defense_evasion_actions,
    "cloud.resourceHijacking": _resource_hijacking,
    "cloud.dataExposure": _cloud_data_exposure,
    "network.commandAndControl": _command_and_control,
    "network.portScan": _port_scan,
    "network.dnsAnomaly": _dns_anomaly,
    "dlp.sensitiveDataExposure": _sensitive_data_exposure,
}


def _cross_alert_cascades(
    cross_signals: list[CrossAlertSignal],
    entity_keys: list[str],
) -> list[dict[str, Any]]:
    """Generate additional actions triggered by cross-alert patterns."""
    from backend.app.services.enrichment.cross_alert import get_scanner

    actions: list[dict[str, Any]] = []
    cs_names = {cs.name for cs in cross_signals}

    if "_multiVectorAttack" in cs_names:
        domains = get_scanner().get_domain_pair(entity_keys)
        domain_set = set(domains)

        if {"identity", "cloud"}.issubset(domain_set):
            actions.append(_act(
                "revoke_all_tokens",
                "Revoke ALL Tokens + Rotate ALL Secrets",
                "Multi-vector attack spanning identity and cloud — revoke tokens and rotate secrets immediately",
                priority="critical", automated=True,
            ))
        if {"identity", "endpoint"}.issubset(domain_set):
            actions.append(_act(
                "isolate_and_revoke",
                "Isolate Endpoint + Revoke Sessions + Force Re-Auth",
                "Multi-vector attack spanning identity and endpoint — isolate host and revoke all sessions",
                priority="critical", automated=True,
            ))

    if "_rapidEscalation" in cs_names:
        actions.append(_act(
            "escalate_to_ic",
            "Escalate to Incident Commander",
            "Rapid escalation detected — 3+ alerts within 5 minutes on the same entity",
            priority="critical",
        ))

    return actions


def _score_to_action_override(score: int, stage: str) -> str | None:
    """Score-based action override as a fallback after signal-based overrides."""
    if score >= 85 and stage in ("exfiltration", "execution", "lateral_movement"):
        return "CONTAIN"
    if score >= 85 and stage in ("privilege_escalation",):
        return "ESCALATE"
    if score < 35:
        return "SUPPRESS"
    if 35 <= score < 60:
        return "REVIEW"
    return None


def get_actions(
    alert_type: str,
    signals: list[Signal],
    cross_signals: list[CrossAlertSignal] | None = None,
    entity_keys: list[str] | None = None,
    score: int = 50,
) -> list[dict[str, Any]]:
    gen = _ACTION_GENERATORS.get(alert_type)
    actions = gen(signals) if gen else []

    stage = _ALERT_TYPE_TO_STAGE.get(alert_type, "execution")
    primary_label = _STAGE_TO_ACTION.get(stage, "INVESTIGATE")

    # Signal-based overrides (highest priority)
    fired = _fired_set(signals)
    if fired & {"data_exfiltration", "data_exfiltration_context", "insider_data_exfil", "bulk_transfer"}:
        primary_label = "CONTAIN"
    elif fired & {"ransomware_chain", "ransomware_context", "ransomware_extortion"}:
        primary_label = "CONTAIN"
    elif fired & {"admin_role_grant", "domain_admin_target", "privilege_level_admin"}:
        primary_label = "ESCALATE"
    elif any(s.name == "noise_flag" and s.fired for s in signals):
        primary_label = "SUPPRESS"
    elif any(s.name == "ir_response" and s.fired for s in signals):
        primary_label = "SUPPRESS"
    else:
        # Score-based override (lower priority than signal-based)
        score_override = _score_to_action_override(score, stage)
        if score_override:
            primary_label = score_override

    for action in actions:
        action["primaryLabel"] = primary_label

    if cross_signals:
        cascade = _cross_alert_cascades(
            cross_signals, entity_keys or [])
        actions.extend(cascade)

    return actions
