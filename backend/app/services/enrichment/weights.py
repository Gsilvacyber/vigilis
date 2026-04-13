"""Central signal weight registry for the Vigilis enrichment engine.

WHY THIS EXISTS: Before this registry, the same signal (e.g., c2_beaconing)
had different weights across extractors (15 in identity, 18 in endpoint, 20
in network). Same threat, different score depending on which extractor caught
it. This violates the principle of deterministic, auditable scoring.

RULE: One signal name = one weight everywhere. If a signal conceptually means
different things in different contexts, give it a different name.

USAGE: All mapper files import `W` and reference `W["signal_name"]` instead
of hardcoding integers. This makes weight tuning a single-file operation.

WEIGHT PHILOSOPHY:
  25-28: Factual, high-confidence threat (impossible travel, known attack tool,
         physical safety, container escape on endpoint)
  18-22: Strong behavioral signal (C2 beaconing, lateral movement, ransomware
         chain, domain admin compromise, insider data exfil)
  12-15: Moderate contextual signal (privileged account, after hours, anomalous
         IP, dormant account, service account)
  8-10:  Weak/environmental signal (unmanaged device, external IP, non-compliant
         device, unsigned binary)
  (-5 to -8):  Contained/blocked (attack prevented, session killed)
  (-25 to -30): Strong noise reduction (IR response, noise flag)
"""
from __future__ import annotations

# ── Positive signals (sorted by weight tier, then alphabetically) ──────

W: dict[str, int] = {
    # ── Tier 5: Factual / Critical (25-28) ───────────────────────────────
    "container_escape": 25,
    "financial_fraud": 25,
    "impossible_travel": 25,
    "impossible_travel_distance": 25,
    "iot_ot_attack": 25,
    "known_attack_tool": 22,
    "ot_protocol_write": 25,
    "physical_safety_risk": 25,
    "ransomware_extortion": 25,

    # ── Tier 4: Strong behavioral (18-22) ─────────────────────────────────
    "account_takeover_context": 20,
    "ad_attack": 22,
    "admin_consent_grant": 20,
    "admin_role_grant": 20,
    "bulk_transfer": 15,
    "c2_beaconing": 18,
    "classified_data": 15,
    "code_secret_exposed": 22,
    "credential_submission": 20,
    "cve_exploited": 22,
    "data_exfiltration": 20,
    "data_exfiltration_context": 20,
    "dc_target": 15,
    "dns_tunnel": 22,
    "dns_tunnel_process": 20,
    "domain_admin_context": 18,
    "domain_admin_target": 18,
    "dormant_account": 18,
    "eventual_mfa_success": 18,
    "financial_impact": 22,
    "full_access_scopes": 18,
    "hidden_rule_flag": 18,
    "insider_data_exfil": 20,
    "insider_persistence": 18,
    "insider_threat": 18,
    "known_bad_hash": 20,
    "lateral_movement": 18,
    "lookalike_domain": 20,
    "masquerading": 18,
    "mfa_fatigue_context": 20,
    "mining_context": 12,
    "multiple_devices_compromised": 18,
    "physical_security_compromised": 20,
    "powershell_on_server": 18,
    "program_hash_mismatch": 22,
    "ransomware_chain": 22,
    "ransomware_context": 20,
    "resignation_on_file": 22,
    "successful_login": 20,
    "supply_chain": 18,
    "supply_chain_attack": 22,
    "supply_chain_process": 20,
    "suspicious_drop_target": 18,
    "wire_transfer_context": 18,
    "shadow_copy_deletion": 22,
    "mass_file_encryption": 22,
    "remote_service_abuse": 20,
    "executive_impersonation": 20,
    "wire_fraud_request": 20,
    "av_disabled": 22,
    "log_cleared": 20,
    "defense_evasion_detected": 20,
    "malicious_attachment": 20,
    "macro_enabled": 18,
    "internal_pivot_detected": 18,

    # ── Tier 3: Moderate contextual (12-15) ───────────────────────────────
    "access_anomaly": 15,
    "anomalous_ip": 12,
    "anomalous_source_ip": 12,
    "broad_scopes": 15,
    "concurrent_sessions": 15,
    "high_item_count": 12,
    "high_risk_identity": 12,
    "high_target_count": 15,
    "living_off_the_land": 15,
    "mfa_vulnerability": 12,
    "multi_country_access": 15,
    "new_app": 12,
    "new_domain": 15,
    "no_change_ticket": 12,
    "offline_access": 12,
    "persistence": 15,
    "persistence_mechanism": 15,
    "phishing_context": 15,
    "privilege_level_admin": 15,
    "privileged_accessor": 15,
    "privileged_account": 15,
    "privileged_mailbox": 12,
    "privileged_target": 12,
    "privileged_user": 12,
    "rare_file": 12,
    "sensitive_scopes": 15,
    "server_target": 12,
    "service_account_process": 12,
    "source_high_risk": 12,
    "successful_auth": 12,
    "targets_executive": 15,
    "targets_finance": 12,
    "unpatched_device": 15,
    "account_dormancy_days": 15,
    "service_account_interactive": 15,
    "svc_unusual_host": 15,
    "port_scan_detected": 15,
    "scan_volume": 12,
    "public_bucket_detected": 18,
    "storage_misconfiguration": 15,
    "pii_detected": 18,
    "classification_violation": 15,
    "crypto_mining_detected": 15,

    # ── Tier 2: Weak / environmental (8-10) ───────────────────────────────
    "actor_identity_mismatch": 15,
    "after_hours": 18,
    "already_privileged": 12,
    "external_forward": 15,
    "first_seen_app": 10,
    "external_geo": 8,
    "external_ip": 10,
    "foreign_origin": 10,
    "mfa_concern": 10,
    "non_compliant_device": 8,
    "rule_obfuscation": 10,
    "server_execution": 10,
    "service_principal_access": 10,
    "service_principal_actor": 8,
    "suspicious_path": 10,
    "unmanaged_device": 8,
    "unknown_publisher": 10,
    "unsigned_binary": 10,
    "urgency_pressure": 10,

    # ── Historical user correlation (Phase 4) ──────────────────────────
    "repeat_offender": 10,
    "escalating_threat": 15,
    "repeated_after_hours": 12,
    "sustained_activity": 12,
    "escalating_exfiltration": 15,

    # ── Internal IP reputation (fills OTX gap for RFC 1918) ──────────
    "sensitive_subnet": 8,
    "internal_ip_repeat_offender": 12,
    "internal_ip_in_incident": 15,
    "internal_ip_cross_domain": 10,

    # ── User behavior baseline (VERIFIED — DB query) ──────────────────
    "first_external_transfer": 18,
    "volume_anomaly": 20,
    "escalating_user_activity": 15,
    "unique_behavior": 12,
    "host_repeat_target": 15,
    "host_in_prior_incident": 18,
    "unresolvable_domain": 15,
    "destination_personal_cloud": 15,
    "known_proxy_vpn": 15,

    # ── Entity graph (detection brain — DB-backed behavioral analysis) ──
    "new_entity_relationship": 20,
    "rare_entity_relationship": 15,
    "entity_graph_anomaly": 18,

    # ── Frequency anomaly (sustained detection after novelty fades) ───────
    "frequency_anomaly": 18,           # verified — today > 3x baseline daily rate
    "frequency_anomaly_critical": 22,  # verified — today > 5x baseline daily rate

    # ── Process-based verified signals (endpoint alerts without IPs) ─────
    "process_on_new_host": 18,
    "rare_process_on_server": 20,
    "known_tool_on_dc": 25,

    # ── Phase 2 new signals (Sysmon EID 10/17/18/19/20/21 + Security Log) ─
    "lsass_access": 22,            # verified — Sysmon EID 10 targeting LSASS
    "wmi_persistence": 22,         # verified — Sysmon EID 19/20/21 (never legit)
    "lateral_movement_pipe": 18,   # verified — PsExec / admin share pipes
    "process_injection": 20,       # verified — T1134 API calls
    "uac_bypass": 18,              # observed — known UAC bypass binaries
    "remote_access_tool": 12,      # inferred — RATs (legitimate use possible)
    "mass_file_create": 15,        # observed — Phase 1.2 aggregation
    "named_pipe_activity": 8,      # observed — Sysmon EID 17/18 base
    "encoded_command": 18,         # inferred/observed — PS encoded command
    "download_cradle": 18,         # verified — T1105 download cradle
    "lolbin_abuse": 15,            # inferred — LOLBin with network args
    "account_creation": 18,        # observed — Security EID 4720

    # ── Phase 3 state-drift signals ──────────────────────────────────────
    "unusual_service_path": 20,    # verified — service outside C:\Windows
    "userland_autorun": 22,        # verified — new autorun in %APPDATA%
    "script_scheduled_task": 20,   # verified — task running powershell/cmd
    "state_drift": 8,              # observed — base for any drift event
    "privilege_escalation_drift": 18,  # verified — new admin user via snapshot

    # ── Cross-alert intelligence (Phase 3) ──────────────────────────────
    "_multiVectorAttack": 18,
    "_crossAlertCorroboration": 12,
    "_rapidEscalation": 15,
    "_dlpCorroborated": 15,

    # ── Threat intel (Phase 4) ────────────────────────────────────────
    "known_malicious_ip": 20,
    "tor_exit_node": 15,
    "recently_registered_domain": 12,
    "known_malicious_domain": 18,
    # "known_bad_hash" already in Tier 4 at 20

    # ── Negative signals (noise reduction) ────────────────────────────────
    "powershell_activity": 1,  # Catch-all: near-zero weight so other signals drive discrimination (was 3)
    "privilege_activity": 1,  # Catch-all: same (was 3)

    # ── PowerShell content-based signals (Step 2 quality improvement) ────
    "ps_registry_access": 8,        # Script touches registry
    "ps_file_write": 10,            # Script writes files
    "ps_network_call": 15,          # Script makes HTTP/socket calls
    "ps_process_spawn": 12,         # Script starts other processes
    "ps_credential_access": 18,     # Script accesses credentials
    "ps_com_object": 10,            # Script uses COM objects
    "ps_wmi_call": 15,              # Script invokes WMI methods
    "ps_service_manipulation": 18,  # Script modifies services
    "ps_event_log_access": 12,      # Script accesses event logs
    "ps_base64_usage": 10,          # Script uses base64

    # ── Process risk-tier signals (Step 4 quality improvement) ───────────
    "known_system_process": -5,     # Negative: known safe Windows system process
    "unknown_process": 10,          # Unknown process warrants investigation

    # ── Domain intelligence signals ──────────────────────────────────────
    "domain_very_new": 22,    # Domain registered < 7 days ago (strong C2/phishing indicator)
    "domain_newly_registered": 18,  # Domain registered < 30 days ago
    "domain_suspicious_tld": 12,    # .xyz, .top, .tk, etc.
    "domain_known_safe": -10,       # Negative: known-safe domain (Microsoft, Google, etc.)

    # ── Negative signals (noise reduction) ────────────────────────────────
    "benign_powershell": -15,  # Known-safe PowerShell script (module imports, Get-*, DSC, etc.)
    "routine_privilege": -10,  # Known system/service account privilege assignment
    "blocked": -8,
    "ir_response": -30,
    "noise_flag": -25,
    "service_account_noise": -15,
    "authorized_admin_activity": -15,
}


def get_weight(signal_name: str) -> int:
    """Get the canonical weight for a signal name.

    Returns 0 if signal is not in the registry (allows dynamic signals
    like action_status to keep their computed weights).
    """
    return W.get(signal_name, 0)


# ── Signal Tier Registry ────────────────────────────────────────────────
# WHY THIS EXISTS: Not all signals carry equal epistemic weight.
# A "verified" signal (external API/DB lookup confirms) is stronger than
# an "inferred" signal (keyword matching on alert text), which is stronger
# than an "observed" signal (reading a pre-populated field from the source
# tool). The tier multiplier in scoring.py applies a discount factor so
# that inferred and observed signals contribute less to the final score.
#
# RULE: If a signal is not listed here, it defaults to "inferred".

SIGNAL_TIERS: dict[str, str] = {
    # Verified — external API or DB lookup confirms
    "known_malicious_ip": "verified",
    "tor_exit_node": "verified",
    "known_malicious_domain": "verified",
    "known_bad_hash": "verified",
    "recently_registered_domain": "verified",
    "repeat_offender": "verified",
    "escalating_threat": "verified",
    "sustained_activity": "verified",
    "escalating_exfiltration": "verified",
    "internal_ip_repeat_offender": "verified",
    "internal_ip_in_incident": "verified",
    "internal_ip_cross_domain": "verified",
    "first_external_transfer": "verified",
    "volume_anomaly": "verified",
    "escalating_user_activity": "verified",
    "unique_behavior": "verified",
    "host_repeat_target": "verified",
    "host_in_prior_incident": "verified",
    "unresolvable_domain": "verified",
    "destination_personal_cloud": "verified",
    "known_proxy_vpn": "verified",
    "_multiVectorAttack": "verified",
    "_crossAlertCorroboration": "verified",
    "_rapidEscalation": "verified",
    "_dlpCorroborated": "verified",
    "impossible_travel_distance": "verified",
    "service_account_interactive": "verified",
    "internal_pivot_detected": "verified",
    "new_entity_relationship": "verified",
    "rare_entity_relationship": "verified",
    "entity_graph_anomaly": "verified",
    "process_on_new_host": "verified",
    "rare_process_on_server": "verified",
    "known_tool_on_dc": "verified",
    "frequency_anomaly": "verified",
    "frequency_anomaly_critical": "verified",
    # Phase 2 new signals
    "lsass_access": "verified",
    "wmi_persistence": "verified",
    "lateral_movement_pipe": "verified",
    "process_injection": "verified",
    "uac_bypass": "observed",
    "remote_access_tool": "inferred",
    "mass_file_create": "observed",
    "named_pipe_activity": "observed",
    "encoded_command": "observed",
    "download_cradle": "verified",
    "lolbin_abuse": "inferred",
    "account_creation": "observed",
    # Phase 3 state-drift signals
    "unusual_service_path": "verified",
    "userland_autorun": "verified",
    "script_scheduled_task": "verified",
    "state_drift": "observed",
    "privilege_escalation_drift": "verified",

    # Observed — reads pre-populated field from source tool
    "anomalous_ip": "observed",
    "anomalous_source_ip": "observed",
    "privileged_account": "observed",
    "privileged_user": "observed",
    "privileged_accessor": "observed",
    "privileged_target": "observed",
    "privilege_level_admin": "observed",
    "already_privileged": "observed",
    "external_geo": "observed",
    "foreign_origin": "observed",
    "multi_country_access": "observed",
    "unmanaged_device": "observed",
    "non_compliant_device": "observed",
    "mfa_concern": "observed",
    "mfa_vulnerability": "observed",
    "high_risk_identity": "observed",
    "service_account_noise": "observed",
    "service_principal_access": "observed",
    "service_principal_actor": "observed",
    "action_status": "observed",
    "external_ip": "observed",
    "resignation_on_file": "observed",
    "cve_exploited": "observed",
    "concurrent_sessions": "observed",
    "bulk_transfer": "observed",
    "classified_data": "observed",
    "access_anomaly": "observed",
    "financial_impact": "observed",
    "financial_fraud": "observed",
    "high_item_count": "observed",
    "sensitive_subnet": "observed",
    "external_forward": "observed",
    "hidden_rule_flag": "observed",
    "rule_obfuscation": "observed",
    "account_dormancy_days": "observed",
    "malicious_attachment": "observed",
    "macro_enabled": "observed",
    "public_bucket_detected": "observed",
    "storage_misconfiguration": "observed",
    "pii_detected": "observed",
    "classification_violation": "observed",

    # Inferred — keyword matching or pattern detection on alert text
    # (everything else defaults to "inferred")

    # Domain intelligence signals
    "domain_very_new": "verified",  # RDAP registration date check
    "domain_newly_registered": "verified",  # RDAP registration date check
    "domain_suspicious_tld": "inferred",  # TLD pattern match
    "domain_known_safe": "verified",  # Known-safe domain list

    # PowerShell content classification
    "ps_registry_access": "observed",
    "ps_file_write": "observed",
    "ps_network_call": "inferred",
    "ps_process_spawn": "inferred",
    "ps_credential_access": "verified",
    "ps_com_object": "observed",
    "ps_wmi_call": "inferred",
    "ps_service_manipulation": "verified",
    "ps_event_log_access": "inferred",
    "ps_base64_usage": "observed",
    "known_system_process": "verified",  # DB-backed path check
    "unknown_process": "inferred",       # Negative list match

    # Catch-all and negative signals — pattern-matched, deterministic
    "powershell_activity": "observed",  # Always fires on PSBL, very low weight
    "privilege_activity": "observed",  # Always fires on EID 4672, very low weight
    "routine_privilege": "verified",  # System/service account check
    "benign_powershell": "verified",  # Regex match against known-safe cmdlets
}


def get_signal_tier(name: str) -> str:
    """Get the tier classification for a signal name.

    Returns "inferred" if the signal is not explicitly listed.
    """
    return SIGNAL_TIERS.get(name, "inferred")
