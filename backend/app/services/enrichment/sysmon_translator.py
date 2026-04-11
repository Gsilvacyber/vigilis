"""Sysmon event translation layer.

Sysmon gives us raw endpoint telemetry (process create, network connect, DNS,
file create, registry modify). Vigilis enrichment expects structured fields
like `_mitreTechnique`, `_scheduledTaskCreated`, `_registryAutorun`, etc.

This module bridges the gap: it inspects incoming events that look like Sysmon
output and synthesizes the structured fields Vigilis already knows how to use,
so the tier-aware signals (ad_attack, persistence, data_exfiltration, etc.)
actually fire on real endpoint data.

The translator is called early in _run_enrichment() when the source tool is
Sysmon. It MUTATES the raw_alert dict in place — adding fields, never removing.

Design principles:
- Detection must be CONSERVATIVE. Better to miss a signal than false-positive
  on legitimate admin work.
- Each detection adds the most specific MITRE technique ID we can justify.
- All matches are case-insensitive.
- Command-line patterns use word boundaries where possible to avoid substring
  false positives (e.g., 'at' matching 'atlas.exe').
"""
from __future__ import annotations

import logging
import re
from typing import Any

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MITRE ATT&CK command-line pattern map
# ---------------------------------------------------------------------------
# Each entry: (compiled regex, technique_id, short_description, structured_field)
# The structured_field is None if we only want to add the MITRE technique.
#
# Order matters — more specific patterns should come first (e.g., "vssadmin
# delete shadows" before just "vssadmin").

_MITRE_PATTERNS: list[tuple[re.Pattern, str, str, str | None]] = [

    # ── T1490: Inhibit System Recovery (ransomware hallmark) ──────────────
    (re.compile(r"\bvssadmin(?:\.exe)?\s+delete\s+shadows", re.I),
     "T1490", "Shadow copy deletion via vssadmin",
     "_shadowCopyDeletion"),
    (re.compile(r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete", re.I),
     "T1490", "Shadow copy deletion via WMIC",
     "_shadowCopyDeletion"),
    (re.compile(r"\bbcdedit(?:\.exe)?\s+.*(?:bootstatuspolicy|recoveryenabled\s+no)", re.I),
     "T1490", "Boot configuration tampering to disable recovery",
     "_shadowCopyDeletion"),
    (re.compile(r"\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstate)", re.I),
     "T1490", "Windows backup catalog deletion",
     "_shadowCopyDeletion"),

    # ── T1070.001: Clear Windows Event Logs (defense evasion) ─────────────
    (re.compile(r"\bwevtutil(?:\.exe)?\s+cl\s+", re.I),
     "T1070.001", "Windows Event Log cleared via wevtutil",
     "_logCleared"),
    (re.compile(r"\bclear[\-]?eventlog\b", re.I),
     "T1070.001", "Event log cleared via PowerShell Clear-EventLog",
     "_logCleared"),
    (re.compile(r"\bfsutil(?:\.exe)?\s+usn\s+deletejournal", re.I),
     "T1070.003", "USN journal deletion (evidence destruction)",
     "_logCleared"),

    # ── T1562.001: Disable/Modify Security Tools ──────────────────────────
    (re.compile(r"\bnetsh(?:\.exe)?\s+advfirewall\s+set.*(?:state\s+off|disable)", re.I),
     "T1562.004", "Windows Firewall disabled via netsh", None),
    (re.compile(r"\b(?:add|set)[\-]?mppreference\s+.*exclusion", re.I),
     "T1562.001", "Windows Defender exclusion added",
     "_defenderTampered"),
    (re.compile(r"\bset[\-]?mppreference\s+.*(?:disable|realtime|protection)", re.I),
     "T1562.001", "Windows Defender protection modified",
     "_defenderTampered"),
    (re.compile(r"\bsc(?:\.exe)?\s+(?:stop|delete)\s+(?:WinDefend|MsMpSvc|Sense|WdNisSvc)", re.I),
     "T1562.001", "Security service stopped via sc",
     "_defenderTampered"),
    (re.compile(r"\bstop[\-]?service\s+.*(?:windefend|msmpsvc|sense)", re.I),
     "T1562.001", "Security service stopped via PowerShell",
     "_defenderTampered"),

    # ── T1059.001: PowerShell encoded/obfuscated commands ─────────────────
    (re.compile(r"\bpowershell\S*\s.*-e(?:nc|ncoded|ncodedcommand)?\s+[A-Za-z0-9+/=]{30,}", re.I),
     "T1059.001", "PowerShell encoded command execution",
     "_encodedCommand"),
    (re.compile(r"\bpowershell\S*\s.*-(?:w(?:indowstyle)?\s+hidden|nop(?:rofile)?)\b", re.I),
     "T1059.001", "PowerShell with hidden window / no profile", None),
    (re.compile(r"\b(?:invoke-expression|iex)\s*\(.*(?:downloadstring|downloadfile|webclient|net\.webrequest)", re.I),
     "T1059.001", "PowerShell download-and-execute cradle",
     "_downloadCradle"),
    (re.compile(r"\bfrombase64string\s*\(.{10,}\)\s*\|\s*iex", re.I),
     "T1059.001", "PowerShell base64 decode and execute",
     "_encodedCommand"),

    # ── T1047: Windows Management Instrumentation ─────────────────────────
    (re.compile(r"\bwmic(?:\.exe)?\s+(?:process|/node)\s+.*call\s+create", re.I),
     "T1047", "WMI remote process creation",
     "_wmiProcessCreate"),
    (re.compile(r"\bget[\-]?wmiobject\s+.*win32_process", re.I),
     "T1047", "PowerShell WMI process query", None),

    # ── T1053: Scheduled Task/Job ─────────────────────────────────────────
    (re.compile(r"\bschtasks(?:\.exe)?\s+/create", re.I),
     "T1053.005", "Scheduled task created via schtasks",
     "_scheduledTaskCreated"),
    (re.compile(r"\bat(?:\.exe)?\s+\\\\", re.I),
     "T1053.002", "At.exe remote scheduled task", None),
    (re.compile(r"\bregister[\-]?scheduledtask\b", re.I),
     "T1053.005", "PowerShell Register-ScheduledTask",
     "_scheduledTaskCreated"),
    (re.compile(r"\bnew[\-]?scheduledtask\b", re.I),
     "T1053.005", "PowerShell New-ScheduledTask",
     "_scheduledTaskCreated"),

    # ── T1543.003: Windows Service Persistence ────────────────────────────
    (re.compile(r"\bsc(?:\.exe)?\s+create\s+", re.I),
     "T1543.003", "Windows service created via sc",
     "_serviceCreated"),
    (re.compile(r"\bnew[\-]?service\b", re.I),
     "T1543.003", "PowerShell New-Service",
     "_serviceCreated"),

    # ── T1547.001: Registry Run Keys / Startup Folder ─────────────────────
    # Note: the path check is flexible — matches \Run, \RunOnce, etc. without
    # caring about the exact prefix (covers both HKCU\Software\... and HKLM\...)
    (re.compile(
        r"\breg(?:\.exe)?\s+add\s+.*CurrentVersion[\\/]+(?:Run|RunOnce|Explorer)",
        re.I,
     ),
     "T1547.001", "Registry Run key added via reg.exe",
     "_registryAutorun"),
    (re.compile(r"\bset[\-]?itemproperty\s+.*CurrentVersion[\\/]+Run", re.I),
     "T1547.001", "PowerShell registry Run key modification",
     "_registryAutorun"),
    (re.compile(r"\bnew[\-]?itemproperty\s+.*CurrentVersion[\\/]+Run", re.I),
     "T1547.001", "PowerShell New-ItemProperty registry Run", "_registryAutorun"),

    # ── T1136: Create Account ─────────────────────────────────────────────
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add", re.I),
     "T1136.001", "Local account created via net user",
     "_accountCreated"),
    (re.compile(r"\bnew[\-]?localuser\b", re.I),
     "T1136.001", "PowerShell local user creation",
     "_accountCreated"),

    # ── T1098: Account Manipulation (add to privileged group) ─────────────
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+(?:local)?group\s+\"?(?:administrators|administrat\w*|domain admins|enterprise admins)\"?\s+\S+\s+/add", re.I),
     "T1098", "Account added to privileged group",
     "_privilegeEscalation"),
    (re.compile(r"\badd[\-]?localgroupmember\s+.*(?:administrators|domain admins)", re.I),
     "T1098", "PowerShell add to admin group",
     "_privilegeEscalation"),

    # ── T1003.001: LSASS Memory Dumping ───────────────────────────────────
    (re.compile(r"\brundll32(?:\.exe)?\s+.*comsvcs\.dll\s*,\s*minidump", re.I),
     "T1003.001", "LSASS dump via comsvcs.dll minidump",
     "_lsassAccess"),
    (re.compile(r"\bprocdump(?:\.exe|64\.exe)?\s+.*(?:-ma\s+lsass|lsass\.exe)", re.I),
     "T1003.001", "LSASS dump via procdump",
     "_lsassAccess"),
    (re.compile(r"\btasklist(?:\.exe)?\s+.*lsass", re.I),
     "T1003.001", "LSASS process inspection", None),
    (re.compile(r"\bsekurlsa::(?:logonpasswords|wdigest|kerberos|msv|ssp|tspkg)", re.I),
     "T1003.001", "Mimikatz sekurlsa module",
     "_lsassAccess"),

    # ── T1018 / T1087 / T1069: Discovery techniques ───────────────────────
    (re.compile(r"\bnltest(?:\.exe)?\s+/dclist", re.I),
     "T1018", "Domain controller discovery via nltest", None),
    (re.compile(r"\bdsquery(?:\.exe)?\s+", re.I),
     "T1018", "Active Directory query via dsquery", None),
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+(?:user|group|localgroup|accounts)\s+/domain", re.I),
     "T1087.002", "Domain account/group enumeration via net", None),
    (re.compile(r"\bget[\-]?adcomputer\b|\bget[\-]?aduser\b|\bget[\-]?adgroup\b", re.I),
     "T1087.002", "PowerShell AD enumeration", None),
    (re.compile(r"\bwhoami(?:\.exe)?\s+(?:/priv|/all|/groups)", re.I),
     "T1033", "User privilege enumeration via whoami", None),

    # ── T1105: Ingress Tool Transfer ──────────────────────────────────────
    (re.compile(r"\bcertutil(?:\.exe)?\s+(?:-|/)urlcache\s+(?:-|/)(?:split\s+)?(?:-|/)?f\s+https?://", re.I),
     "T1105", "certutil used to download file (LOLBin abuse)",
     "_downloadCradle"),
    (re.compile(r"\bbitsadmin(?:\.exe)?\s+.*(?:transfer|addfile)", re.I),
     "T1197", "BITS job created (possible ingress)",
     "_downloadCradle"),
    (re.compile(r"\binvoke[\-]?webrequest\s+.*(?:-outfile|-o\s+)", re.I),
     "T1105", "PowerShell Invoke-WebRequest download", None),

    # ── T1218: Signed Binary Proxy Execution (LOLBins) ────────────────────
    (re.compile(r"\brundll32(?:\.exe)?\s+.*javascript:", re.I),
     "T1218.011", "Rundll32 JavaScript execution", None),
    (re.compile(r"\bregsvr32(?:\.exe)?\s+.*(?:/s\s+/u\s+|scrobj\.dll|https?://)", re.I),
     "T1218.010", "Regsvr32 script/remote execution (Squiblydoo)", None),
    (re.compile(r"\bmshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)", re.I),
     "T1218.005", "Mshta remote script execution", None),
    (re.compile(r"\binstallutil(?:\.exe)?\s+.*\.dll", re.I),
     "T1218.004", "InstallUtil code execution", None),
    (re.compile(r"\bmsbuild(?:\.exe)?\s+.*\.xml", re.I),
     "T1127.001", "MSBuild inline code execution", None),
    (re.compile(r"\bcsc(?:\.exe)?\s+.*\.cs", re.I),
     "T1027.004", "Compile after delivery (csc.exe)", None),

    # ── T1140: Deobfuscate/Decode Files ───────────────────────────────────
    (re.compile(r"\bcertutil(?:\.exe)?\s+.*(?:-|/)decode", re.I),
     "T1140", "certutil base64 decode",
     "_encodedCommand"),

    # ── T1569.002: System Services (PsExec / remote exec) ────────────────
    (re.compile(r"\bpsexec(?:\.exe|64\.exe)?\s+\\\\", re.I),
     "T1569.002", "PsExec remote execution",
     "_remoteExecution"),
    (re.compile(r"\bwmiexec\b|\bsmbexec\b|\bdcomexec\b", re.I),
     "T1569.002", "Impacket-style remote exec", None),

    # ── T1021.002: SMB/Windows Admin Shares ───────────────────────────────
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+use\s+\\\\\S+\\\\(?:C|ADMIN|IPC)\$", re.I),
     "T1021.002", "Admin share connection via net use", None),

    # ── T1078.002: Valid Accounts - Domain Accounts (runas /netonly) ─────
    (re.compile(r"\brunas(?:\.exe)?\s+.*(?:/netonly|/profile)", re.I),
     "T1078.002", "runas with alternate credentials", None),
]


# ---------------------------------------------------------------------------
# Suspicious parent-child process relationships
# ---------------------------------------------------------------------------
# Office apps should never spawn shells. Browsers should never spawn
# administrative tools. These fire even without command line evidence.

_SUSPICIOUS_PARENT_CHILD: list[tuple[re.Pattern, re.Pattern, str, str]] = [
    # Office → shell/script interpreters
    (re.compile(r"(?:winword|excel|powerpnt|outlook|msaccess)\.exe$", re.I),
     re.compile(r"(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$", re.I),
     "T1566.001", "Office app spawning script interpreter (phishing payload)"),
    # Browser → shell/script interpreters
    (re.compile(r"(?:chrome|firefox|msedge|iexplore|opera|brave)\.exe$", re.I),
     re.compile(r"(?:cmd|powershell|pwsh|wscript|cscript)\.exe$", re.I),
     "T1566.002", "Browser spawning script interpreter (drive-by)"),
    # PDF reader → shell
    (re.compile(r"(?:acrord32|acrobat|foxitreader|sumatrapdf)\.exe$", re.I),
     re.compile(r"(?:cmd|powershell|pwsh|wscript|cscript)\.exe$", re.I),
     "T1566.001", "PDF reader spawning shell (exploit payload)"),
    # Services → shell (lateral movement indicator)
    (re.compile(r"\bservices\.exe$", re.I),
     re.compile(r"(?:cmd|powershell|pwsh)\.exe$", re.I),
     "T1543.003", "services.exe spawning shell (service install via remote exec)"),
]


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _is_sysmon_source(raw_alert: dict[str, Any]) -> bool:
    """Check if this alert came from a Sysmon feed."""
    # The case_service wraps raw_alert before passing to enrichment, but the
    # source field isn't always in raw_alert itself. Check multiple locations.
    source_name = str(
        raw_alert.get("_sourceName")
        or raw_alert.get("sourceName")
        or ""
    ).lower()
    source_tool = str(
        raw_alert.get("_sourceTool")
        or raw_alert.get("_sourceSiem")
        or ""
    ).lower()
    # Also check for Sysmon-specific field markers
    has_sysmon_markers = bool(
        raw_alert.get("_sysmonEventId")
        or (raw_alert.get("process") and raw_alert.get("commandLine"))
    )
    return (
        "sysmon" in source_name
        or "sysmon" in source_tool
        or has_sysmon_markers
    )


def translate_sysmon_event(raw_alert: dict[str, Any]) -> int:
    """Inspect a Sysmon-sourced alert and add structured fields in place.

    Returns the number of structured fields added. Called early in the
    enrichment pipeline before extractors run, so downstream tier upgrades
    can fire on the added fields.

    Mutates raw_alert by adding:
      - `_mitreTechnique` (single) and `mitre.techniques` (list) when detected
      - `_shadowCopyDeletion`, `_logCleared`, `_encodedCommand`, etc. booleans
      - `_lolbinAbuse` marker when LOLBin patterns detected
      - `_suspiciousParentChild` when parent/child process relationship flagged
    """
    if not _is_sysmon_source(raw_alert):
        return 0

    added = 0
    techniques_found: set[str] = set()

    # Collect all command-line-like text for pattern matching
    candidates: list[str] = []
    for field in ("commandLine", "_commandLine", "process", "_processName"):
        val = raw_alert.get(field)
        if isinstance(val, str) and val:
            candidates.append(val)

    # Also include the description if present (fallback)
    desc = raw_alert.get("description") or raw_alert.get("_description") or ""
    if isinstance(desc, str) and desc:
        candidates.append(desc)

    combined = " ".join(candidates)

    # ── Command-line MITRE pattern matching ───────────────────────────────
    if combined:
        for pattern, technique, label, field_name in _MITRE_PATTERNS:
            if pattern.search(combined):
                techniques_found.add(technique)
                if field_name and raw_alert.get(field_name) is not True:
                    raw_alert[field_name] = True
                    added += 1
                    _log.debug(
                        "sysmon_translator: added %s=true (%s %s)",
                        field_name, technique, label,
                    )

    # ── Suspicious parent/child process detection ────────────────────────
    parent = str(raw_alert.get("_parentProcess") or raw_alert.get("parentImage") or "")
    child = str(raw_alert.get("process") or raw_alert.get("_processName") or "")
    if parent and child:
        # Normalize to basenames for comparison
        parent_base = parent.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        child_base = child.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        for parent_rx, child_rx, technique, label in _SUSPICIOUS_PARENT_CHILD:
            if parent_rx.search(parent_base) and child_rx.search(child_base):
                techniques_found.add(technique)
                if raw_alert.get("_suspiciousParentChild") is not True:
                    raw_alert["_suspiciousParentChild"] = True
                    raw_alert["_suspiciousParentChildReason"] = label
                    added += 2
                    _log.debug(
                        "sysmon_translator: parent=%s child=%s → %s %s",
                        parent_base, child_base, technique, label,
                    )
                break  # one parent/child match is enough

    # ── LOLBin in suspicious path ─────────────────────────────────────────
    lolbins = {
        "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
        "mshta.exe", "installutil.exe", "msbuild.exe", "wmic.exe",
        "powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe",
    }
    if child:
        child_lower = child.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if child_lower in lolbins:
            # Check if this LOLBin is being used with network/download args
            if combined and any(
                kw in combined.lower()
                for kw in ("http://", "https://", "ftp://", "urlcache", "downloadstring")
            ):
                if raw_alert.get("_lolbinAbuse") is not True:
                    raw_alert["_lolbinAbuse"] = True
                    added += 1

    # ── Write MITRE technique fields if we found any ─────────────────────
    if techniques_found:
        # Flat field for backward compat
        if not raw_alert.get("_mitreTechnique"):
            # Pick the most specific (longest) technique ID
            most_specific = max(techniques_found, key=len)
            raw_alert["_mitreTechnique"] = most_specific
            added += 1

        # Structured mitre field that the tier-aware functions check
        existing_mitre = raw_alert.get("mitre")
        if not isinstance(existing_mitre, dict):
            raw_alert["mitre"] = {"techniques": sorted(techniques_found)}
            added += 1
        else:
            existing_techs = set(existing_mitre.get("techniques") or [])
            merged = existing_techs | techniques_found
            if merged != existing_techs:
                existing_mitre["techniques"] = sorted(merged)
                added += 1

    return added
