from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from backend.app.schemas.case_v0_2 import (
    Actor,
    App,
    BulkTarget,
    CaseReadiness,
    CaseV0_2,
    Confidence,
    ConfidenceLabel,
    Customer,
    Device,
    Disposition,
    Enrichment,
    Entities,
    FileEntity,
    IPAddressEntity,
    Identity,
    IdentityType,
    ImpactSummary,
    Mailbox,
    Source,
)
from backend.app.schemas.case_v0_2 import Severity as CanonicalSeverity
from backend.app.services.enrichment import enrich_debug as _enrich_debug


# ── Context-aware recommended actions ──────────────────────────────────
# Each alert type has a decision tree of actions instead of a flat list.
# Actions include SIEM query templates and branching logic based on what
# signals fired during enrichment.  This replaces the old boilerplate.
#
# Format: list of dicts with {action, priority, condition?, query?}
#   action:    What to do (human-readable)
#   priority:  "P1" (immediate), "P2" (within 1h), "P3" (during shift)
#   condition: When this step is relevant (optional)
#   query:     SIEM query template (optional, uses {USER}, {IP}, {HOST} placeholders)

_MANUAL_STEPS: dict[str, list[str]] = {
    "identity.suspiciousSignIn": [
        "[P1] If IP flagged as malicious/Tor: immediately disable account and revoke active sessions",
        "[P1] If MFA not enrolled: escalate to identity team NOW — account has no second factor",
        "[P2] If MFA enrolled and succeeded: check challenge timestamps — user may have approved under duress (fatigue attack)",
        "[P2] Query SIEM: index=auth user={USER} earliest=-24h | stats count by src_ip, country, result | where count>3",
        "[P3] If after-hours login from new device/location: contact user via out-of-band channel (phone, not email)",
        "[P3] Review device compliance state — unmanaged device accessing corporate resources is higher risk",
    ],
    "identity.passwordSpray": [
        "[P1] Query SIEM: index=auth src_ip={IP} earliest=-1h | stats dc(user) as targets, count by result | where targets>5",
        "[P1] If any successful auth post-spray: immediately reset that account and revoke tokens",
        "[P2] Check if source IP is known proxy/VPN service — spray through anonymization infrastructure is APT-grade",
        "[P2] Block source IP at firewall/WAF and add to deny list",
        "[P3] Review all accounts that received spray attempts — force password rotation for targeted accounts",
    ],
    "identity.mfaFatigue": [
        "[P1] If user approved an MFA prompt they didn't initiate: account is compromised — disable immediately",
        "[P1] Query SIEM: index=mfa user={USER} earliest=-2h | stats count by result, push_type | sort -count",
        "[P2] Check for session tokens issued after the MFA approval — attacker may have active session",
        "[P3] Switch user to phishing-resistant MFA (FIDO2/passkey) — push notifications are vulnerable to fatigue",
    ],
    "identity.oauthConsentRisk": [
        "[P1] If app is from unverified publisher: revoke consent immediately via admin portal",
        "[P1] Query SIEM: index=audit action=consent app_name={APP} | stats count by user, scope",
        "[P2] Review granted scopes — Mail.ReadWrite + Files.ReadWrite.All = full mailbox+file access",
        "[P3] Check if other users also consented to same app — could be widespread compromise",
    ],
    "identity.privilegeElevation": [
        "[P1] If no change ticket exists: unauthorized privilege escalation — disable the elevated permissions NOW",
        "[P1] Query SIEM: index=audit user={USER} action=roleAssignment earliest=-24h | table time, role, target, actor",
        "[P2] If change ticket exists: verify the ticket approver matches the actor — could be forged/stolen ticket",
        "[P3] Audit all actions taken under the new privileges in the last hour",
    ],
    "endpoint.malwareDetection": [
        "[P1] If AV/EDR quarantined the file: verify quarantine succeeded — check process is actually terminated",
        "[P1] Query EDR: host={HOST} process_hash={HASH} | table time, pid, parent_process, network_connections",
        "[P2] If file executed before quarantine: assume compromise — isolate endpoint from network",
        "[P2] Check VirusTotal/sandbox for file hash — determine malware family and capabilities",
        "[P3] Scan sibling endpoints in same subnet for same hash — check for lateral spread",
    ],
    "endpoint.suspiciousProcess": [
        "[P1] If known attack tool (mimikatz, cobalt strike, etc.): isolate endpoint immediately",
        "[P1] Query EDR: host={HOST} parent_process={PARENT} earliest=-1h | table time, child_process, command_line, user",
        "[P2] If LOLBin (certutil, mshta, regsvr32): check command-line args for download/decode patterns",
        "[P2] If PowerShell with -enc or -e flag: decode the base64 payload and check for C2/download URLs",
        "[P3] Review parent process chain — legitimate admin script vs attacker lateral movement",
    ],
    "email.forwardingRule": [
        "[P1] If forwarding to external domain: disable rule immediately and check for data exfiltration",
        "[P1] Query SIEM: index=o365 user={USER} operation=Set-InboxRule earliest=-7d | table time, rule_name, forward_to",
        "[P2] Check if user's password was recently changed or if there was a suspicious login before rule creation",
        "[P3] Review mailbox audit log for bulk email reads/exports in the last 24h",
    ],
    "email.phishingDetected": [
        "[P1] Query SIEM: index=email sender={SENDER} earliest=-24h | stats dc(recipient) as targets, count by subject",
        "[P1] If recipient clicked link: check proxy logs for the URL — was credential page loaded?",
        "[P2] Block sender domain and URL at email gateway + web proxy",
        "[P2] Search for similar emails to other users — phishing campaigns target multiple victims",
        "[P3] If credentials were submitted: reset password + revoke tokens + check for post-compromise activity",
    ],
    "cloud.secretStoreAccessAnomaly": [
        "[P1] If service principal accessed secrets from unusual IP: rotate ALL accessed secrets immediately",
        "[P1] Query SIEM: index=cloud resource=keyvault user={USER} earliest=-24h | stats count by operation, secret_name, src_ip",
        "[P2] Check if accessed secrets are still valid — attacker may have already used them",
        "[P3] Review service principal permissions — principle of least privilege audit",
    ],
    "network.impossibleGeoAccess": [
        "[P1] If two locations are >500km apart within <2h: not physically possible — one session is attacker",
        "[P2] Query SIEM: index=auth user={USER} earliest=-48h | stats values(country) as countries, dc(src_ip) as ip_count by _time span=1h",
        "[P2] Check if either IP is a known VPN/proxy — may explain travel anomaly",
        "[P3] If both sessions are active: kill the more recent session and force re-auth with MFA",
    ],
    "network.dataExfiltration": [
        "[P1] If destination is personal cloud (Dropbox, GDrive, Mega): block upload + preserve evidence",
        "[P1] Query SIEM: index=proxy user={USER} dest_ip={DST_IP} earliest=-7d | stats sum(bytes) as total_bytes by dest_domain | sort -total_bytes",
        "[P2] Identify what data was transferred — DLP logs, file access audit, classification labels",
        "[P2] If volume >100MB: likely not accidental — escalate to data loss prevention team",
        "[P3] Check if user has upcoming departure date or performance issues (insider threat indicators)",
    ],
    "cloud.iamPrivilegeEscalation": [
        "[P1] If no change ticket exists: unauthorized IAM escalation -- revert role assignment immediately",
        "[P1] Query SIEM: index=cloud action=AttachRolePolicy OR action=CreateRole user={USER} earliest=-24h | stats count by action, role_name, src_ip",
        "[P2] If role includes AdministratorAccess or IAMFullAccess: check for follow-on API calls using new permissions",
        "[P2] Review CloudTrail: was the role assumption from expected service or anomalous principal?",
        "[P3] Audit all actions taken under the escalated role in the last hour",
        "[P3] Check if escalation matches known attack pattern (AssumeRole chaining, cross-account pivot)",
    ],
    "cloud.suspiciousApiCall": [
        "[P1] If API call modifies security groups or network ACLs: check for unauthorized access paths",
        "[P1] Query SIEM: index=cloud user={USER} earliest=-4h | stats count by eventName, sourceIPAddress, userAgent | sort -count",
        "[P2] If API call involves data plane (S3 GetObject, DynamoDB Scan): check for data exfiltration volume",
        "[P2] Check if calling identity normally makes these API calls -- compare against 30-day baseline",
        "[P3] Review user agent string -- AWS CLI vs SDK vs console may indicate attack tooling",
        "[P3] If from assumed role: trace role trust policy back to original identity",
    ],
    "identity.impossibleTravel": [
        "[P1] If two locations >500km apart within <2h: one session is attacker — kill the newer session",
        "[P1] Query SIEM: index=auth user={USER} earliest=-48h | stats values(country) as countries, dc(src_ip) as ips by _time span=1h",
        "[P2] Check if either IP is a known VPN/proxy service — may explain travel anomaly",
        "[P2] Review device fingerprints — if same device ID from both locations, likely token theft",
        "[P3] Contact user to verify travel schedule via out-of-band channel",
    ],
    "identity.dormantAccountLogin": [
        "[P1] If account dormant >180 days: likely compromised credentials — disable immediately",
        "[P1] Query SIEM: index=auth user={USER} earliest=-365d | stats count by _time span=30d | where count>0",
        "[P2] Check if password was recently reset or credentials leaked in known breach",
        "[P2] If service account: verify who requested reactivation and check change ticket",
        "[P3] Review all activity from this account in last 24h for signs of compromise",
    ],
    "identity.serviceAccountAbuse": [
        "[P1] If interactive logon from service account: disable account and investigate immediately",
        "[P1] Query SIEM: index=auth user={USER} logon_type=interactive OR logon_type=10 earliest=-7d | stats count by src_ip, hostname",
        "[P2] Compare source host against known service hosts — unusual host indicates compromise",
        "[P2] Check if credential was harvested from a compromised endpoint (look for T1003)",
        "[P3] Audit all service account permissions — principle of least privilege review",
    ],
    "email.businessEmailCompromise": [
        "[P1] If wire transfer requested: immediately alert finance team to HOLD all pending transfers",
        "[P1] Query SIEM: index=email sender_domain={SENDER} earliest=-30d | stats dc(recipient) as targets, count by subject",
        "[P2] Check sender domain registration — lookalike domains registered <30 days are suspicious",
        "[P2] Compare sender email headers against known legitimate correspondence",
        "[P3] Search for similar emails to other employees — BEC campaigns target multiple people",
        "[P3] If funds transferred: initiate wire recall immediately (banks have 24-72h window)",
    ],
    "email.maliciousAttachment": [
        "[P1] If attachment was opened: isolate endpoint immediately and check for execution artifacts",
        "[P1] Query SIEM: index=email attachment_hash={HASH} earliest=-24h | stats dc(recipient) as targets",
        "[P2] Submit attachment hash to VirusTotal/sandbox — determine malware family and capabilities",
        "[P2] Check if macro/script executed — look for child processes spawned from Office apps",
        "[P3] Quarantine all emails with same attachment hash across the organization",
    ],
    "endpoint.ransomwareDetection": [
        "[P1] Immediately isolate affected endpoint from network — prevent lateral spread",
        "[P1] Query EDR: host={HOST} process_name=vssadmin OR process_name=bcdedit earliest=-1h | table time, command_line, user",
        "[P2] Check for shadow copy deletion — vssadmin delete shadows indicates active ransomware",
        "[P2] Identify ransomware family from ransom note or encrypted file extension",
        "[P3] Scan all endpoints in same subnet for same IOCs — check for lateral spread",
    ],
    "endpoint.lateralMovement": [
        "[P1] If PsExec/WMI from non-admin workstation: block source host immediately",
        "[P1] Query SIEM: index=endpoint src_host={HOST} dest_port=445 OR dest_port=135 earliest=-4h | stats dc(dest_host) as targets",
        "[P2] Check if source credentials are compromised — look for credential dumping on source host",
        "[P2] Map the lateral movement path: source -> intermediate -> destination hosts",
        "[P3] Review all accessed systems for data staging or exfiltration indicators",
    ],
    "endpoint.credentialDumping": [
        "[P1] If LSASS access detected: assume all credentials on that host are compromised",
        "[P1] Query EDR: host={HOST} target_process=lsass.exe earliest=-2h | table time, source_process, user, command_line",
        "[P2] Force password reset for ALL accounts that were logged into the compromised host",
        "[P2] Check for DCSync — if domain controller targeted, all domain hashes may be compromised",
        "[P3] Deploy credential guard and LSASS protection on affected endpoints",
    ],
    "endpoint.persistenceMechanism": [
        "[P1] If scheduled task or service created by unknown process: disable and preserve for analysis",
        "[P1] Query SIEM: host={HOST} (EventID=4698 OR EventID=7045 OR EventID=13) earliest=-24h | table time, task_name, command",
        "[P2] Check task/service command line for encoded payloads or download cradles",
        "[P2] Compare against baseline — is this a known admin tool or attacker persistence?",
        "[P3] Scan for additional persistence mechanisms: registry run keys, startup folder, WMI subscriptions",
    ],
    "endpoint.defenseEvasion": [
        "[P1] If AV/EDR disabled: re-enable immediately and investigate who/what disabled it",
        "[P1] Query SIEM: host={HOST} (EventID=1102 OR EventID=4688 process_name=wevtutil) earliest=-4h | table time, user, command_line",
        "[P2] Check if event logs were cleared — missing logs during incident window is highly suspicious",
        "[P2] Look for AMSI bypass, ETW patching, or process injection artifacts",
        "[P3] Validate that all security controls are operational across the environment",
    ],
    "cloud.resourceHijacking": [
        "[P1] If crypto mining process detected (xmrig, stratum protocol): terminate process and isolate instance immediately",
        "[P1] Query SIEM: index=cloud instance_id={HOST} earliest=-24h | stats count by process_name, dest_ip, dest_port | where dest_port=3333 OR dest_port=4444",
        "[P2] Check for container escape indicators — privileged containers or host PID namespace access",
        "[P2] Review cloud billing for anomalous compute spend spikes in the last 48 hours",
        "[P3] Audit IAM credentials on the affected instance — attacker may have harvested cloud keys",
        "[P3] Scan all instances in the same VPC for similar mining processes or C2 connections",
    ],
    "cloud.dataExposure": [
        "[P1] If public bucket/container detected: remove public access immediately and enable bucket logging",
        "[P1] Query SIEM: index=cloud resource_type=storage action=PutBucketPolicy OR action=PutBucketAcl earliest=-7d | table time, user, bucket, policy",
        "[P2] Inventory all objects in the exposed storage — determine if PII, PHI, or classified data was accessible",
        "[P2] Check access logs for external downloads during the exposure window",
        "[P3] Review all storage resources in the account for similar misconfigurations",
        "[P3] Enable preventive guardrails — SCPs or organization policies to block public storage creation",
    ],
    "network.commandAndControl": [
        "[P1] If known C2 framework detected (Cobalt Strike, Sliver): isolate affected host immediately",
        "[P1] Query SIEM: index=proxy dest_ip={IP} earliest=-7d | timechart span=5m count | where count>0",
        "[P2] Analyze beaconing interval — regular periodic callbacks indicate active C2 channel",
        "[P2] Check TLS certificate on destination — self-signed or recently issued certs are suspicious",
        "[P3] Block destination IP/domain at firewall and review all hosts that communicated with it",
    ],
    "network.portScan": [
        "[P1] If scan originates from internal host: check host for compromise — legitimate scanning requires change ticket",
        "[P1] Query SIEM: index=firewall src_ip={IP} earliest=-1h | stats dc(dest_port) as ports_scanned, dc(dest_ip) as hosts_scanned | where ports_scanned>50",
        "[P2] Determine scan type (SYN, connect, UDP) — SYN scans indicate attacker reconnaissance",
        "[P2] Check if scanner IP matches authorized vulnerability scanning tools (Nessus, Qualys)",
        "[P3] Review all hosts that responded to the scan — open services may be vulnerable",
        "[P3] If external source: block IP at perimeter and check threat intel for known scanner",
    ],
    "network.dnsAnomaly": [
        "[P1] If DNS tunneling tool detected (iodine, dnscat2, dns2tcp): isolate source host immediately",
        "[P1] Query SIEM: index=dns src_ip={IP} earliest=-24h | stats avg(query_length) as avg_len, dc(query) as unique_queries by dest_domain | where avg_len>50",
        "[P2] Analyze query entropy — high entropy subdomains indicate encoded data exfiltration",
        "[P2] Check for TXT record queries with base64-encoded payloads — common C2 data channel",
        "[P3] Block the suspicious domain at DNS resolver and review all clients that queried it",
        "[P3] Correlate with proxy logs — DNS anomaly often accompanies web-based exfiltration",
    ],
    "dlp.sensitiveDataExposure": [
        "[P1] If PII/PHI/PCI data confirmed in unauthorized location: initiate data breach response procedure",
        "[P1] Query SIEM: index=dlp user={USER} earliest=-7d | stats count by policy_name, file_name, destination | sort -count",
        "[P2] Identify data classification level and volume — determines regulatory notification requirements",
        "[P2] Check if user has resignation on file or insider threat indicators",
        "[P3] Review DLP policy exceptions — determine if this is a policy gap or active violation",
        "[P3] Assess downstream exposure — was data shared externally, posted publicly, or sent to personal accounts",
    ],
}

_RISK_DETAILS: dict[str, dict[str, str]] = {
    "identity.suspiciousSignIn": {
        "critical": "Account takeover likely - active unauthorized session detected",
        "high": "Credential compromise probable - anomalous sign-in from hostile geography",
        "medium": "Unusual sign-in activity - requires user verification",
        "low": "Minor sign-in anomaly - routine review",
    },
    "identity.passwordSpray": {
        "critical": "Active credential breach - successful spray with privileged account hit",
        "high": "Password spray campaign - successful logins detected post-spray",
        "medium": "Spray activity detected - monitor for successful authentication",
        "low": "Low-volume spray attempt - likely automated scanning",
    },
    "identity.mfaFatigue": {
        "critical": "MFA bypass confirmed - attacker has session access",
        "high": "MFA fatigue attack with eventual prompt acceptance",
        "medium": "Repeated MFA challenges from anomalous source",
        "low": "Unusual MFA prompt pattern - user verification recommended",
    },
    "identity.oauthConsentRisk": {
        "critical": "Malicious app consent - broad scope access to tenant data",
        "high": "Risky OAuth consent - unknown publisher with sensitive scopes",
        "medium": "OAuth consent from unverified app - review required",
        "low": "Low-risk app consent - publisher known, limited scope",
    },
    "identity.privilegeElevation": {
        "critical": "Unauthorized privilege escalation - admin role granted outside process",
        "high": "Suspicious privilege change - actor elevated own or unfamiliar account",
        "medium": "Role assignment flagged - verify approval chain",
        "low": "Minor permission change - standard workflow",
    },
    "endpoint.malwareDetection": {
        "critical": "Active malware - rare unsigned binary executing from suspicious path",
        "high": "Malware detected - quarantine and containment needed",
        "medium": "Suspicious file flagged - investigation recommended",
        "low": "Low-confidence detection - likely false positive",
    },
    "endpoint.suspiciousProcess": {
        "critical": "Active exploitation - LOLBin chain with encoded payload executing",
        "high": "Suspicious process chain - encoded command with anomalous parent",
        "medium": "Process anomaly detected - review execution context",
        "low": "Minor process anomaly - likely administrative activity",
    },
    "email.forwardingRule": {
        "critical": "Data exfiltration via email - external forwarding on executive mailbox",
        "high": "Suspicious forwarding rule - external destination, recently created",
        "medium": "New forwarding rule detected - verify with mailbox owner",
        "low": "Internal forwarding rule - likely legitimate",
    },
    "email.phishingDetected": {
        "critical": "Targeted spear-phishing against executive - credential harvesting link clicked",
        "high": "Phishing email with malicious payload detected - user may have interacted",
        "medium": "Suspected phishing email flagged - review sender and content",
        "low": "Low-confidence phishing detection - likely marketing or spam",
    },
    "cloud.secretStoreAccessAnomaly": {
        "critical": "Secret store breach - unauthorized service principal accessing credentials",
        "high": "Anomalous secret access - new app identity accessing key vault after hours",
        "medium": "Unusual secret store access pattern - review required",
        "low": "Minor secret access anomaly - likely service update",
    },
    "network.impossibleGeoAccess": {
        "critical": "Impossible travel - admin account authenticated from two countries simultaneously",
        "high": "Impossible travel detected - successful auth from conflicting geolocations",
        "medium": "Geographic access anomaly - verify VPN or travel schedule",
        "low": "Minor geo anomaly - likely VPN-related",
    },
    "network.dataExfiltration": {
        "critical": "Active data exfiltration - large unauthorized transfer to external destination",
        "high": "Significant data transfer to suspicious destination detected",
        "medium": "Unusual data transfer volume detected - review required",
        "low": "Minor data transfer anomaly - likely legitimate",
    },
    "cloud.iamPrivilegeEscalation": {
        "critical": "Unauthorized IAM escalation -- admin-level permissions granted outside change process",
        "high": "Suspicious IAM privilege change -- role escalation without approval",
        "medium": "IAM role modification detected -- verify change management process",
        "low": "Minor IAM change -- routine role adjustment",
    },
    "cloud.suspiciousApiCall": {
        "critical": "Suspicious API activity -- high-volume sensitive operations from anomalous source",
        "high": "Anomalous API call pattern -- potential automated attack or data access",
        "medium": "Unusual API activity flagged -- review caller identity and purpose",
        "low": "Minor API anomaly -- likely legitimate automation",
    },
    "identity.impossibleTravel": {
        "critical": "Simultaneous active sessions from impossible locations — account compromised",
        "high": "Login from new country within hours of previous location — likely credential theft",
        "medium": "Geographic anomaly detected — verify with user travel schedule",
        "low": "Minor location change — may be VPN or proxy usage",
    },
    "identity.dormantAccountLogin": {
        "critical": "Dormant privileged account reactivated with anomalous access — active breach",
        "high": "Account inactive >180 days now active — credential compromise probable",
        "medium": "Dormant account login detected — verify reactivation authorization",
        "low": "Recently dormant account login — routine review recommended",
    },
    "identity.serviceAccountAbuse": {
        "critical": "Service account interactive logon from unauthorized host — credential theft confirmed",
        "high": "Service account used outside baseline — unusual host or interactive session",
        "medium": "Service account anomaly detected — verify against expected usage pattern",
        "low": "Minor service account deviation — likely configuration change",
    },
    "email.businessEmailCompromise": {
        "critical": "Active BEC with wire transfer request — financial fraud in progress",
        "high": "Executive impersonation with payment or sensitive data request detected",
        "medium": "Suspected BEC — lookalike domain or urgency indicators present",
        "low": "Low-confidence BEC indicators — review sender legitimacy",
    },
    "email.maliciousAttachment": {
        "critical": "Malicious attachment opened — endpoint compromise likely, isolate immediately",
        "high": "Known malware attachment detected — check if recipient interacted",
        "medium": "Suspicious attachment flagged — sandbox analysis recommended",
        "low": "Low-confidence attachment detection — likely false positive",
    },
    "endpoint.ransomwareDetection": {
        "critical": "Active ransomware — shadow copies deleted, mass encryption in progress",
        "high": "Ransomware indicators detected — containment and isolation required",
        "medium": "Suspected ransomware activity — investigation recommended",
        "low": "Low-confidence ransomware detection — likely false positive",
    },
    "endpoint.lateralMovement": {
        "critical": "Active lateral movement — attacker spreading across network with stolen credentials",
        "high": "Lateral movement detected — remote service abuse from compromised host",
        "medium": "Suspicious remote access pattern — verify administrative activity",
        "low": "Minor lateral movement indicator — routine review",
    },
    "endpoint.credentialDumping": {
        "critical": "Active credential theft — LSASS dump or DCSync targeting domain credentials",
        "high": "Credential dumping detected — privileged account credentials at risk",
        "medium": "Suspected credential access activity — investigation recommended",
        "low": "Low-confidence credential access — likely security tool or admin activity",
    },
    "endpoint.persistenceMechanism": {
        "critical": "Unauthorized persistence — attacker backdoor established on critical system",
        "high": "Persistence mechanism detected — scheduled task or service created by suspicious process",
        "medium": "Unusual persistence activity — verify against administrative baselines",
        "low": "Minor persistence indicator — likely legitimate software installation",
    },
    "endpoint.defenseEvasion": {
        "critical": "Security controls disabled — AV/EDR tampered with on critical infrastructure",
        "high": "Defense evasion detected — event logs cleared or security tools disabled",
        "medium": "Suspected evasion technique — AMSI bypass or process injection indicators",
        "low": "Low-confidence evasion indicator — routine review recommended",
    },
    "cloud.resourceHijacking": {
        "critical": "Active crypto mining -- compute resources hijacked with container escape confirmed",
        "high": "Resource hijacking detected -- unauthorized mining processes consuming cloud resources",
        "medium": "Suspicious resource usage pattern -- possible mining or unauthorized workload",
        "low": "Minor compute anomaly -- review for unauthorized resource consumption",
    },
    "cloud.dataExposure": {
        "critical": "Critical data exposure -- classified data in publicly accessible storage with external downloads",
        "high": "Cloud storage exposed -- public bucket or container with sensitive data detected",
        "medium": "Storage misconfiguration detected -- review access controls and data classification",
        "low": "Minor storage configuration finding -- routine compliance review",
    },
    "network.commandAndControl": {
        "critical": "Active C2 channel -- known attack framework beaconing to external infrastructure",
        "high": "C2 beaconing detected -- regular callbacks to suspicious external destination",
        "medium": "Potential C2 communication -- anomalous periodic outbound connections",
        "low": "Minor network anomaly -- low-confidence C2 indicator",
    },
    "network.portScan": {
        "critical": "Aggressive reconnaissance -- high-volume port scan from compromised internal host",
        "high": "Active port scanning detected -- unauthorized network reconnaissance in progress",
        "medium": "Port scan activity flagged -- verify against authorized scanning schedule",
        "low": "Low-volume scan detected -- likely automated or incidental",
    },
    "network.dnsAnomaly": {
        "critical": "Active DNS exfiltration -- tunneling tool confirmed with high-volume encoded queries",
        "high": "DNS anomaly detected -- high-entropy queries indicating data exfiltration channel",
        "medium": "Unusual DNS query pattern -- review for potential tunneling or covert channel",
        "low": "Minor DNS anomaly -- likely misconfiguration or benign software",
    },
    "dlp.sensitiveDataExposure": {
        "critical": "Active data breach -- PII/PHI/PCI data confirmed in unauthorized external location",
        "high": "Sensitive data exposure -- classification policy violation with exfiltration indicators",
        "medium": "DLP policy violation detected -- sensitive data in unauthorized location",
        "low": "Minor DLP finding -- low-volume or low-classification data involved",
    },
}

_FALLBACK_RISK: dict[str, str] = {
    "critical": "Critical - immediate response required",
    "high": "High - investigate within 1 hour",
    "medium": "Medium - review within shift",
    "low": "Low - batch review",
}

_COMPLEXITY_BONUS: dict[str, int] = {
    "identity.passwordSpray": 5,
    "network.impossibleGeoAccess": 5,
    "identity.oauthConsentRisk": 3,
    "cloud.secretStoreAccessAnomaly": 3,
    "endpoint.malwareDetection": 2,
}


def _filter_steps_by_context(
    steps: list[str], score: int, fired_signals: set[str],
) -> list[str]:
    """Remove investigation steps irrelevant to this case's context.

    Low-score cases don't need P1 Tor-hunting steps. Cases without specific
    signals shouldn't show conditional steps about those signals.
    """
    if not steps:
        return steps

    # Low-score cases: only show P3 (general review) steps
    if score < 30:
        filtered = [s for s in steps if "[P3]" in s]
        return filtered if filtered else steps[:2]  # Fallback: first 2 steps

    # Medium-score: skip signal-specific conditional steps when those signals didn't fire
    filtered = []
    for step in steps:
        # Skip Tor/malicious-IP steps when no Tor or malicious IP signal fired
        if ("malicious/Tor" in step or "Tor:" in step) and not (
            fired_signals & {"known_malicious_ip", "tor_exit_node"}
        ):
            continue
        # Skip MFA steps when MFA signals didn't fire and score is low
        if "MFA" in step and "mfa_concern" not in fired_signals and score < 50:
            continue
        filtered.append(step)

    return filtered if filtered else steps


def _fill_query_templates(steps: list[str], raw_alert: dict[str, Any]) -> list[str]:
    """Replace SIEM query placeholders with actual entity values."""
    identity = raw_alert.get("identity") or {}
    if not isinstance(identity, dict):
        identity = {}
    upn = identity.get("upn", "")

    # Get source IP and destination IP separately
    all_ips = []
    for ip_obj in raw_alert.get("ips", []) or []:
        if isinstance(ip_obj, dict):
            addr = ip_obj.get("ipAddress", "")
            role = ip_obj.get("role", "")
            if addr and addr != "0.0.0.0":
                all_ips.append((addr, role))
        elif isinstance(ip_obj, str) and ip_obj and ip_obj != "0.0.0.0":
            all_ips.append((ip_obj, ""))

    src_ip = ""
    dst_ip = ""
    # Anomalous IP = source; if 2+ IPs, second is likely destination
    for addr, role in all_ips:
        if role == "anomalous" and not src_ip:
            src_ip = addr
    # If no anomalous found, first IP is source
    if not src_ip and all_ips:
        src_ip = all_ips[0][0]
    # Destination = second IP (different from source), or explicit dst_ip field
    for addr, role in all_ips:
        if addr != src_ip and not dst_ip:
            dst_ip = addr
    # Fallback: check raw flat fields for dst_ip
    if not dst_ip:
        dst_ip = raw_alert.get("dst_ip") or raw_alert.get("destination_ip") or ""
    ip = src_ip or dst_ip

    device = raw_alert.get("device") or {}
    if not isinstance(device, dict):
        device = {}
    hostname = device.get("hostname", "")

    app_data = raw_alert.get("app") or {}
    if not isinstance(app_data, dict):
        app_data = {}

    replacements = {
        "{USER}": upn or "<user>",
        "{IP}": ip or "<ip>",
        "{DST_IP}": dst_ip or src_ip or "<dest_ip>",
        "{HOST}": hostname or "<host>",
        "{SENDER}": raw_alert.get("_mailFrom") or raw_alert.get("sender") or "<sender>",
        "{HASH}": (raw_alert.get("file") or {}).get("sha256", "") or raw_alert.get("_fileHash") or "<hash>",
        "{APP}": app_data.get("name", "") or "<app>",
        "{PARENT}": raw_alert.get("_parentProcess") or "<parent_process>",
    }

    filled = []
    for step in steps:
        s = step
        for placeholder, value in replacements.items():
            s = s.replace(placeholder, value)
        filled.append(s)
    return filled


def _compute_impact_summary(
    alert_type: str,
    confidence_label: str,
    fired_signal_count: int,
    entity_type_count: int,
    is_privileged: bool,
) -> ImpactSummary:
    # Documented estimates based on SOC analyst task benchmarks
    components = ["3 min: automated alert triage"]
    total = 3

    # Signal analysis time: 1 min per signal, cap 8
    signal_mins = min(fired_signal_count, 8)
    if signal_mins > 0:
        total += signal_mins
        components.append(f"{signal_mins} min: analyzed {fired_signal_count} behavioral signals")

    # Multi-entity correlation
    if entity_type_count >= 3:
        total += 3
        components.append("3 min: cross-entity correlation")

    # Privileged account assessment
    if is_privileged:
        total += 2
        components.append("2 min: privileged account risk assessment")

    # Playbook recommendation
    total += 2
    components.append("2 min: playbook recommendation")

    total = min(total, 45)

    type_risks = _RISK_DETAILS.get(alert_type, {})
    risk = type_risks.get(confidence_label, _FALLBACK_RISK.get(confidence_label, "Unknown"))

    manual_steps = _MANUAL_STEPS.get(alert_type, [
        "Manual alert triage",
        "Context gathering from multiple tools",
        "Severity assessment",
    ])
    # Append the time-saved basis as the last manual step entry for transparency
    basis = "Estimated based on: " + "; ".join(components)
    manual_steps_with_basis = list(manual_steps) + [basis]

    return ImpactSummary(
        risk=risk,
        timeSavedMinutes=total,
        manualStepsReplaced=manual_steps_with_basis,
    )


def _count_entity_types(
    ips: list,
    device: Device,
    app: App,
    mailbox: Mailbox,
    file_entity: FileEntity,
    identity: Identity,
) -> int:
    count = 0
    if ips:
        count += 1
    if device.hostname or device.deviceId:
        count += 1
    if app.name or app.appId:
        count += 1
    if mailbox.primaryAddress:
        count += 1
    if file_entity.fileName or file_entity.sha256:
        count += 1
    if identity.userId or identity.upn:
        count += 1
    return count


def _compute_readiness(
    alert_type: str,
    confidence_score: int,
    confidence_label: str,
    identity: Identity,
    device: Device,
    app: App,
    fired_signal_count: int = 1,
) -> CaseReadiness:
    missing: list[str] = []
    if not identity.userId and not identity.upn:
        missing.append("identity (userId or upn)")
    if alert_type.startswith("endpoint.") and not device.hostname:
        missing.append("device hostname")
    if alert_type == "identity.oauthConsentRisk" and not app.name:
        missing.append("app name")
    if fired_signal_count == 0:
        missing.append("no enrichment signals fired")

    ready = confidence_score >= 40 and len(missing) == 0 and fired_signal_count > 0
    return CaseReadiness(
        readyForAction=ready,
        missingContext=missing,
        confidenceLevel=confidence_label,
    )


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _identity_from_raw(raw: dict[str, Any]) -> Identity:
    identity_type = raw.get("identityType") or raw.get("type") or "unknown"
    if identity_type not in {"user", "service_principal", "managed_identity", "unknown"}:
        identity_type = "unknown"

    # Sanitize privilegeTier to only allow valid values
    _VALID_TIERS = {"standard", "privileged", "admin", "service_account"}
    _priv = raw.get("privilegeTier")
    _new_priv = raw.get("newPrivilegeTier")
    if _priv and _priv not in _VALID_TIERS:
        _priv = None
    if _new_priv and _new_priv not in _VALID_TIERS:
        _new_priv = None

    return Identity(
        identityType=identity_type,  # type: ignore[arg-type]
        userId=raw.get("userId"),
        upn=raw.get("upn"),
        displayName=raw.get("displayName"),
        servicePrincipalId=raw.get("servicePrincipalId"),
        privilegeTier=_priv,
        newPrivilegeTier=_new_priv,
        mfaStatus=raw.get("mfaStatus"),
        riskLevel=raw.get("riskLevel"),
    )


def _actor_from_raw(raw: Optional[dict[str, Any]]) -> Actor:
    raw = raw or {}
    identity = _identity_from_raw(raw)
    return Actor(**identity.model_dump())


def _device_from_raw(raw: Optional[dict[str, Any]]) -> Device:
    raw = raw or {}
    return Device(
        deviceId=raw.get("deviceId"),
        hostname=raw.get("hostname"),
        managed=raw.get("managed", True),
        os=raw.get("os"),
        compliance=raw.get("compliance"),
        identificationStatus=raw.get("identificationStatus", "unknown"),
    )


def _ips_from_raw(raw_ips: Any) -> list[IPAddressEntity]:
    if raw_ips is None:
        return []
    if isinstance(raw_ips, list):
        ips: list[IPAddressEntity] = []
        for item in raw_ips:
            if isinstance(item, str):
                ips.append(IPAddressEntity(role="observed", ipAddress=item))
            elif isinstance(item, dict):
                role = item.get("role") or "observed"
                if role not in {"observed", "anomalous", "legitimate", "prior_known"}:
                    role = "observed"
                geo = item.get("geo") or {}
                ips.append(
                    IPAddressEntity(
                        role=role,  # type: ignore[arg-type]
                        ipAddress=item.get("ipAddress") or item.get("ip"),
                        geo=geo,
                    )
                )
        return ips
    if isinstance(raw_ips, str):
        return [IPAddressEntity(role="observed", ipAddress=raw_ips)]
    return []


def _app_from_raw(raw: Optional[dict[str, Any]]) -> App:
    raw = raw or {}
    return App(
        name=raw.get("name"),
        clientApp=raw.get("clientApp"),
        appId=raw.get("appId"),
        publisher=raw.get("publisher"),
        scopes=raw.get("scopes") or [],
        firstSeenInTenantAt=raw.get("firstSeenInTenantAt"),
    )


def _mailbox_from_raw(raw: Optional[dict[str, Any]]) -> Mailbox:
    raw = raw or {}
    return Mailbox(
        primaryAddress=raw.get("primaryAddress"),
        displayName=raw.get("displayName"),
        forwardingAddress=raw.get("forwardingAddress"),
        ruleName=raw.get("ruleName"),
    )


def _file_from_raw(raw: Optional[dict[str, Any]]) -> FileEntity:
    raw = raw or {}
    return FileEntity(
        fileName=raw.get("fileName"),
        filePath=raw.get("filePath"),
        sha256=raw.get("sha256"),
        signer=raw.get("signer"),
        prevalence=raw.get("prevalence"),
    )


def _bulk_target_from_raw(raw: Optional[dict[str, Any]]) -> BulkTarget:
    raw = raw or {}
    return BulkTarget(
        count=raw.get("count") or 0,
        successCount=raw.get("successCount") or 0,
        succeededAccounts=raw.get("succeededAccounts") or [],
        sampleTargets=raw.get("sampleTargets") or [],
    )


def normalize_case_from_request(
    *,
    tenant: dict[str, Any],
    source: dict[str, Any],
    alert_type: str,
    title: Optional[str],
    description: Optional[str],
    severity: CanonicalSeverity,
    event_time: datetime,
    raw_alert: dict[str, Any],
) -> CaseV0_2:
    ingested_time = _now_utc()
    enriched_time = ingested_time

    customer = Customer(
        name=tenant["name"],
        environment=tenant.get("environment", "prod"),
        industry=tenant.get("industry"),
    )

    source_model = Source(
        sourceSystem=source["sourceSystem"],
        sourceName=source["sourceName"],
        sourceAlertId=source["sourceAlertId"],
        sourceSeverity=source["sourceSeverity"],
        sourceUrl=source.get("sourceUrl"),
    )

    _tenant_id = tenant.get("tenantId") if isinstance(tenant, dict) else None
    debug = _enrich_debug(
        alert_type=alert_type,
        severity=severity,
        raw_alert=raw_alert,
        event_time=event_time,
        tenant_id=_tenant_id,
    )
    enrichment_result = debug.result
    signals = debug.all_signals
    fired_count = sum(1 for s in signals if s.fired)

    confidence = Confidence(
        score=enrichment_result.confidence_score,
        label=enrichment_result.confidence_label,
        explanation=enrichment_result.confidence_explanation,
    )

    disposition = Disposition(status="open", setBy=None, setAt=None, notes=None)
    bulk_target = _bulk_target_from_raw(raw_alert.get("bulkTarget"))

    identity_raw = raw_alert.get("identity")
    if not isinstance(identity_raw, dict):
        user_val = raw_alert.get("user")
        if isinstance(user_val, dict):
            identity_raw = user_val
        elif isinstance(user_val, str):
            identity_raw = {"upn": user_val, "userId": user_val}
        else:
            identity_raw = {}
    identity = _identity_from_raw(identity_raw)
    actor_raw = raw_alert.get("actor")
    actor = _actor_from_raw(actor_raw if actor_raw else identity.model_dump())

    device = _device_from_raw(raw_alert.get("device"))
    app = _app_from_raw(raw_alert.get("app"))
    mailbox = _mailbox_from_raw(raw_alert.get("mailbox"))
    file_entity = _file_from_raw(raw_alert.get("file"))
    ips = _ips_from_raw(raw_alert.get("ips") or raw_alert.get("ipAddresses"))

    entities = Entities(
        identity=identity,
        actor=actor,
        device=device,
        ips=ips,
        app=app,
        mailbox=mailbox,
        file=file_entity,
    )

    # Backfill structured entity data from enrichment signals
    _tor_detected = any(
        s.fired and (
            "tor" in (s.label or "").lower()
            or s.name == "tor_exit_node"
            or "tor_exit" in (s.name or "")
        )
        for s in signals
    )
    if _tor_detected:
        for ip_entity in (entities.ips or []):
            if ip_entity.role in ("source", "anomalous", "external"):
                ip_entity.geo.isTorExit = True

    is_privileged = identity.privilegeTier in ("privileged", "admin")
    entity_type_count = _count_entity_types(ips, device, app, mailbox, file_entity, identity)

    impact = _compute_impact_summary(
        alert_type, enrichment_result.confidence_label,
        fired_count, entity_type_count, is_privileged,
    )
    # Fill SIEM query placeholders with actual entity values from the alert
    impact.manualStepsReplaced = _fill_query_templates(
        impact.manualStepsReplaced, raw_alert,
    )
    # Filter steps based on case context — don't show P1 Tor steps for a score-5 normal login
    _fired_signal_names = {s["signal"] for s in enrichment_result.confidence_explanation if isinstance(s, dict)}
    impact.manualStepsReplaced = _filter_steps_by_context(
        impact.manualStepsReplaced,
        enrichment_result.confidence_score,
        _fired_signal_names,
    )

    readiness = _compute_readiness(
        alert_type, enrichment_result.confidence_score,
        enrichment_result.confidence_label, identity, device, app,
        fired_signal_count=fired_count,
    )

    enrichment = Enrichment(
        riskScore=enrichment_result.confidence_score,
        enrichmentNotes=enrichment_result.enrichment_notes,
        impactSummary=impact,
        caseReadiness=readiness,
    )

    audit = {
        "rulesetVersion": "rules.v0.2",
        "enrichmentLatencyMs": 0,
        "enrichmentSources": ["rule_engine_v1"],
        "operatorOverrides": [],
        "processingErrors": [],
    }

    outputs: dict = {"webhooks": [source_model.sourceUrl] if source_model.sourceUrl else [], "soarConnectors": []}

    # Store MITRE data if available
    mitre_data = raw_alert.get("mitre")
    if mitre_data:
        outputs["mitre"] = mitre_data

    retention = {"storeMode": "cached", "ttlDays": 14, "redacted": True}

    recommended_playbook = enrichment_result.recommended_playbook
    recommended_actions = enrichment_result.recommended_actions

    # Use source alert name or additional context for better titles/descriptions
    source_alert_name = raw_alert.get("_sourceAlertName", "")
    additional_ctx = raw_alert.get("_additionalContext", "")
    resolved_title = title or source_alert_name or f"{alert_type} alert"
    resolved_description = description or additional_ctx or ""

    # Generate description from entities if still empty or too short
    if not resolved_description or len(resolved_description) < 20:
        _type_labels = {
            "identity.suspiciousSignIn": "Suspicious sign-in",
            "identity.passwordSpray": "Password spray attack",
            "identity.mfaFatigue": "MFA fatigue attack",
            "identity.oauthConsentRisk": "Risky OAuth consent",
            "identity.privilegeElevation": "Privilege escalation",
            "endpoint.malwareDetection": "Malware detected",
            "endpoint.suspiciousProcess": "Suspicious process execution",
            "email.forwardingRule": "Email forwarding rule created",
            "email.phishingDetected": "Phishing email detected",
            "cloud.secretStoreAccessAnomaly": "Secret store access anomaly",
            "network.impossibleGeoAccess": "Impossible travel detected",
            "network.dataExfiltration": "Data exfiltration detected",
            "endpoint.ransomwareDetection": "Ransomware detected",
            "endpoint.lateralMovement": "Lateral movement detected",
            "endpoint.credentialDumping": "Credential dumping detected",
            "endpoint.persistenceMechanism": "Persistence mechanism detected",
            "endpoint.defenseEvasion": "Defense evasion detected",
            "identity.impossibleTravel": "Impossible travel detected",
            "identity.dormantAccountLogin": "Dormant account login",
            "identity.serviceAccountAbuse": "Service account abuse detected",
            "email.businessEmailCompromise": "Business email compromise detected",
            "email.maliciousAttachment": "Malicious attachment detected",
        }
        label = _type_labels.get(alert_type, alert_type)
        user_str = identity.upn or identity.displayName or ""
        device_str = ""
        if hasattr(entities, 'device') and entities.device and entities.device.hostname != "unknown-host":
            device_str = f" on {entities.device.hostname}"
        geo_str = ""
        for ip_ent in (entities.ips or []):
            if ip_ent.geo and ip_ent.geo.country and ip_ent.geo.country != "unknown":
                geo_str = f" from {ip_ent.geo.country}"
                break
        priv_str = ""
        if identity.privilegeTier in ("admin", "privileged"):
            priv_str = f" — {identity.privilegeTier} account"
        if user_str:
            resolved_description = f"{label} by {user_str}{device_str}{geo_str}{priv_str}"
        else:
            resolved_description = f"{label}{device_str}{geo_str}"

    # Compute quality flags with detailed context
    quality_flags: list[str] = []
    _upn = identity.upn or ""
    _has_user = _upn not in ("unknown@upload", "unknown", "") and bool(_upn)
    _has_device = bool(device.hostname) and device.hostname != "unknown-host"
    _has_ips = bool(ips)

    if not _has_user:
        missing_parts = []
        if not _has_user:
            missing_parts.append("user identity")
        if not _has_device:
            missing_parts.append("device hostname")
        if not _has_ips:
            missing_parts.append("source IP")
        fallback = ""
        if _has_device and not _has_user:
            fallback = ". Fallback: device-based correlation"
        elif _has_ips and not _has_user:
            fallback = ". Fallback: IP-based correlation"
        detail = f"Missing: {', '.join(missing_parts)}{fallback}" if missing_parts else ""
        quality_flags.append(f"INCOMPLETE_DATA: {detail}" if detail else "INCOMPLETE_DATA")

    if enrichment_result.confidence_score < 30 and severity in ("critical", "high"):
        quality_flags.append("LOW_CONFIDENCE")
    if not enrichment_result.confidence_explanation:
        quality_flags.append("NO_SIGNALS")
    enrichment.qualityFlags = quality_flags

    return CaseV0_2(
        tenantId=tenant["tenantId"],
        customer=customer,
        sources=[source_model],
        alertType=alert_type,
        title=resolved_title,
        description=resolved_description,
        timestamps={
            "eventTime": event_time,
            "ingestedTime": ingested_time,
            "enrichedTime": enriched_time,
        },
        severity=severity,
        confidence=confidence,
        disposition=disposition,
        bulkTarget=bulk_target,
        entities=entities,
        enrichment=enrichment,
        recommendedPlaybook=recommended_playbook,
        recommendedActions=recommended_actions,
        outputs=outputs,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        retention=retention,  # type: ignore[arg-type]
    )
