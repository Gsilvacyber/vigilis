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

from backend.app.core.metrics import sysmon_eid_fork_hits, sysmon_pattern_hits

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

    # ── T1134: Process Injection APIs (Phase 2.4) ────────────────────────
    # These Win32 API calls are extremely rare in legitimate software but
    # are required for classic injection techniques: CreateRemoteThread,
    # DLL injection, APC injection, reflective injection.
    (re.compile(r"\b(?:CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|QueueUserAPC|NtMapViewOfSection|RtlCreateUserThread)\b", re.I),
     "T1134", "Process injection API call",
     "_processInjection"),

    # ── T1548.002: UAC Bypass (Phase 2.4) ────────────────────────────────
    # Tightened: require the auto-elevated binary to be invoked as a command-
    # line argument (e.g., `powershell -Command fodhelper.exe ...`) or in
    # combination with registry manipulation, NOT just a bare name match.
    # Otherwise every IT admin opening Event Viewer would trip this.
    (re.compile(r"(?:powershell|cmd|wscript|cscript|rundll32|mshta)\S*\s+.*\b(?:fodhelper|computerdefaults|sdclt|compmgmtlauncher|wsreset)\.exe\b", re.I),
     "T1548.002", "UAC bypass binary invoked from script interpreter",
     "_uacBypass"),
    (re.compile(r"\bHKCU\\\\Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command\b", re.I),
     "T1548.002", "UAC bypass via HKCU ms-settings hijack",
     "_uacBypass"),

    # ── T1219: Remote Access Tools (Phase 2.4) ───────────────────────────
    # RATs widely abused for persistence. Often legitimate on IT endpoints —
    # fire as inferred signal only (no structured field).
    (re.compile(r"\b(?:anydesk|teamviewer|splashtop|supremo|connectwisecontrol|screenconnect|logmein|remoteutilities|atera|syncro|ninjaone)\.exe\b", re.I),
     "T1219", "Remote access tool installation",
     "_remoteAccessTool"),

    # ── T1055 subvariants: SetWindowsHookEx / SetThreadContext (Phase 4.4)
    (re.compile(r"\b(?:SetWindowsHookEx|SetThreadContext|NtQueueApcThread|NtUnmapViewOfSection)\b", re.I),
     "T1055", "Process injection via hook/context manipulation",
     "_processInjection"),

    # ── T1027.004: Compile After Delivery (Phase 4.4) ────────────────────
    # PowerShell Add-Type + CSharp source with dangerous imports = compile
    # attack payload on target. Legitimate modules (PSWindowsUpdate, PowerCLI)
    # use Add-Type with plain .NET types — we require suspicious imports.
    (re.compile(r"\bAdd-Type\s+-TypeDefinition\s+.*(?:DllImport|kernel32|ntdll|advapi32|Marshal\.AllocHGlobal)", re.I),
     "T1027.004", "PowerShell Add-Type with native DLL import",
     "_encodedCommand"),

    # ── T1570: Lateral Tool Transfer - admin share copy (Phase 4.4) ──────
    # Tightened: require writable target (C$/ADMIN$) AND a non-standard
    # destination path. Bare `robocopy \\server\C$\...` fires on WSUS/SCCM/
    # PDQ Deploy, so we also require a suspicious subpath (\Temp, \Users,
    # \Windows\Tasks) to reduce FPs.
    (re.compile(r"\b(?:copy|xcopy|robocopy|Copy-Item)\s+.*\\\\[^\\]+\\(?:C|ADMIN)\$\\(?:Temp|Users|Windows\\Tasks|PerfLogs)\\", re.I),
     "T1570", "File copy to admin share with suspicious destination path",
     "_lateralMovementPipe"),

    # ── T1113: Screen Capture (Phase 4.4) ────────────────────────────────
    # Win32 GDI / .NET calls used by malware to capture screens
    (re.compile(r"\b(?:BitBlt|Graphics\.CopyFromScreen|GetDC\s*\(|CreateCompatibleBitmap)\b", re.I),
     "T1113", "Screen capture API call", None),

    # ── T1087.001: Local Account Discovery (Phase 4.4) ───────────────────
    # `net user` without /domain is local account enumeration
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+user\s*(?!.*\/domain)(?!\s+\S+\s+\S+\s+/add)(?:\s|$)", re.I),
     "T1087.001", "Local account enumeration via net user", None),

    # ═══════════════════════════════════════════════════════════════════════
    # MITRE Coverage Expansion — 20+ new techniques (quality council Step 3)
    # Covers gaps in: Discovery, Collection, Impact, Defense Evasion,
    # Lateral Movement, Execution, Persistence
    # ═══════════════════════════════════════════════════════════════════════

    # ── T1012: Query Registry ────────────────────────────────────────────
    (re.compile(r"\breg(?:\.exe)?\s+query\s+HK", re.I),
     "T1012", "Registry query for configuration data", None),

    # ── T1016: System Network Configuration Discovery ────────────────────
    (re.compile(r"\b(?:ipconfig|ifconfig)(?:\.exe)?\s+(?:/all|/displaydns|/flushdns)", re.I),
     "T1016", "Network configuration discovery", None),
    (re.compile(r"\bnetsh(?:\.exe)?\s+(?:interface|wlan|firewall)\s+show", re.I),
     "T1016", "Network configuration via netsh", None),

    # ── T1049: System Network Connections Discovery ──────────────────────
    (re.compile(r"\bnetstat(?:\.exe)?\s+.*-(?:a|n|o|b|p)", re.I),
     "T1049", "Active network connections enumeration", None),
    (re.compile(r"\bGet-NetTCPConnection\b|\bGet-NetUDPEndpoint\b", re.I),
     "T1049", "PowerShell network connection discovery", None),

    # ── T1057: Process Discovery ─────────────────────────────────────────
    (re.compile(r"\btasklist(?:\.exe)?\s+(?:/v|/svc|/fi)", re.I),
     "T1057", "Process listing with details", None),

    # ── T1069: Permission Groups Discovery ───────────────────────────────
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+(?:local)?group\s*(?!.*\/add)(?:\s|$)", re.I),
     "T1069.001", "Local group enumeration", None),

    # ── T1082: System Information Discovery ──────────────────────────────
    (re.compile(r"\bsysteminfo(?:\.exe)?\b", re.I),
     "T1082", "System information discovery", None),
    (re.compile(r"\bhostname(?:\.exe)?\b", re.I),
     "T1082", "Hostname discovery", None),

    # ── T1083: File and Directory Discovery ──────────────────────────────
    (re.compile(r"\bdir\s+.*(?:/s|/b|/a)\b", re.I),
     "T1083", "Recursive file/directory listing", None),
    (re.compile(r"\bGet-ChildItem\s+.*-Recurse\b", re.I),
     "T1083", "PowerShell recursive file search", None),
    (re.compile(r"\btree(?:\.exe)?\s+(?:/f|/a)", re.I),
     "T1083", "Directory tree enumeration", None),

    # ── T1112: Modify Registry ───────────────────────────────────────────
    (re.compile(r"\breg(?:\.exe)?\s+(?:add|delete)\s+HK(?!.*CurrentVersion[\\/]+Run)", re.I),
     "T1112", "Registry modification (non-Run key)", None),

    # ── T1036: Masquerading ──────────────────────────────────────────────
    (re.compile(r"\brename\s+.*\.exe\s+.*(?:svchost|csrss|lsass|services|explorer)\.exe", re.I),
     "T1036.003", "Rename masquerading as system process", None),
    (re.compile(r"\bcopy\s+.*\.exe\s+.*(?:svchost|csrss|lsass|services)\.exe", re.I),
     "T1036.003", "Copy masquerading as system process", None),

    # ── T1489: Service Stop (Impact) ─────────────────────────────────────
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+stop\s+(?!WinDefend|MsMpSvc|Sense)\S+", re.I),
     "T1489", "Service stopped via net stop", None),
    (re.compile(r"\bstop[\-]?service\s+(?!.*(?:windefend|msmpsvc|sense))\S+", re.I),
     "T1489", "Service stopped via PowerShell", None),

    # ── T1529: System Shutdown/Reboot (Impact) ───────────────────────────
    (re.compile(r"\bshutdown(?:\.exe)?\s+.*(?:/s|/r|/f|/t\s+0)", re.I),
     "T1529", "System shutdown or forced reboot", None),
    (re.compile(r"\bRestart-Computer\b|\bStop-Computer\b", re.I),
     "T1529", "PowerShell system shutdown/restart", None),

    # ── T1561: Disk Wipe (Impact) ────────────────────────────────────────
    (re.compile(r"\bformat(?:\.exe)?\s+[a-zA-Z]:\s+/(?:y|q|fs)", re.I),
     "T1561.002", "Disk format (data destruction)", None),
    (re.compile(r"\bcipher(?:\.exe)?\s+/w:", re.I),
     "T1561.001", "Secure file deletion via cipher", None),

    # ── T1119: Automated Collection ──────────────────────────────────────
    (re.compile(r"\bforfiles(?:\.exe)?\s+.*(?:/s|/c|\.doc|\.xls|\.pdf|\.pst)", re.I),
     "T1119", "Automated file collection via forfiles", None),
    (re.compile(r"\bGet-ChildItem\s+.*-Include\s+\*\.(?:doc|xls|pdf|pst|key|pem|pfx)", re.I),
     "T1119", "PowerShell automated document collection", None),

    # ── T1115: Clipboard Data ────────────────────────────────────────────
    (re.compile(r"\bGet-Clipboard\b|\b\[Windows\.Clipboard\]|\bpowershell.*clip\b", re.I),
     "T1115", "Clipboard data access", None),

    # ── T1074: Data Staged ───────────────────────────────────────────────
    (re.compile(r"\bCompress-Archive\b|\btar\s+.*-c|\b7z(?:\.exe)?\s+a\b", re.I),
     "T1074.001", "Data staged via compression for exfiltration", None),

    # ── T1021.001: Remote Desktop Protocol ───────────────────────────────
    (re.compile(r"\bmstsc(?:\.exe)?\s+/v:", re.I),
     "T1021.001", "RDP connection initiated", None),
    (re.compile(r"\breg(?:\.exe)?\s+add\s+.*Terminal\s*Server.*fDenyTSConnections.*0", re.I),
     "T1021.001", "RDP enabled via registry", None),

    # ── T1091: Replication Through Removable Media ───────────────────────
    (re.compile(r"\bxcopy\s+.*[a-eA-E]:\\.*\s+[a-eA-E]:", re.I),
     "T1091", "File copy to removable media", None),

    # ── T1497: Virtualization/Sandbox Evasion ────────────────────────────
    (re.compile(r"\b(?:Get-WmiObject|Get-CimInstance)\s+Win32_(?:ComputerSystem|BIOS).*(?:VMware|VirtualBox|QEMU|Hyper-V|Xen)", re.I),
     "T1497.001", "VM/sandbox detection query", None),
    (re.compile(r"\bSbieDll\.dll\b|\bdbghelp\.dll.*IsDebuggerPresent\b", re.I),
     "T1497.001", "Sandbox/debugger evasion check", None),

    # ── T1048: Exfiltration Over Alternative Protocol ────────────────────
    (re.compile(r"\bnslookup(?:\.exe)?\s+.*-type=(?:TXT|AAAA|MX)\s+.*\.", re.I),
     "T1048.003", "DNS-based data exfiltration (TXT/MX query)", None),

    # ── T1486: Data Encrypted for Impact (ransomware encryption) ────────
    (re.compile(r"\b(?:AESManaged|RijndaelManaged|RSACryptoServiceProvider|CryptoStream)\b", re.I),
     "T1486", "Cryptographic API usage (potential ransomware encryption)", None),

    # ═══════════════════════════════════════════════════════════════════════
    # MITRE Coverage Expansion #2 — 15 new techniques (60+ base target)
    # Covers gaps in: Discovery, Collection, Defense Evasion, Credential
    # Access, Lateral Movement, Command and Control
    # ═══════════════════════════════════════════════════════════════════════

    # ── T1010: Application Window Discovery ─────────────────────────────
    (re.compile(r"\bGet-Process\b.*\bMainWindowTitle\b", re.I),
     "T1010", "Application window title enumeration via PowerShell", None),
    (re.compile(r"\b(?:EnumWindows|GetForegroundWindow|GetWindowText)\b", re.I),
     "T1010", "Application window enumeration via Win32 API", None),

    # ── T1007: System Service Discovery ─────────────────────────────────
    (re.compile(r"\bsc(?:\.exe)?\s+query(?:\s+type=\s*(?:service|driver|all)|\s+state=|\s+\S+)", re.I),
     "T1007", "Service enumeration via sc query", None),
    (re.compile(r"\bGet-Service\b", re.I),
     "T1007", "Service enumeration via PowerShell Get-Service", None),
    (re.compile(r"\bwmic(?:\.exe)?\s+service\s+(?:list|get|where)", re.I),
     "T1007", "Service enumeration via WMIC", None),

    # ── T1518: Software Discovery ───────────────────────────────────────
    (re.compile(r"\bwmic(?:\.exe)?\s+product\s+(?:list|get|where)", re.I),
     "T1518", "Installed software enumeration via WMIC", None),
    (re.compile(r"\bGet-WmiObject\s+Win32_Product\b", re.I),
     "T1518", "Installed software enumeration via PowerShell WMI", None),
    (re.compile(r"\bGet-CimInstance\s+Win32_Product\b", re.I),
     "T1518", "Installed software enumeration via PowerShell CIM", None),
    (re.compile(r"\breg(?:\.exe)?\s+query\s+.*Uninstall\b", re.I),
     "T1518", "Installed software enumeration via registry", None),

    # ── T1518.001: Security Software Discovery ──────────────────────────
    (re.compile(r"\bGet-MpComputerStatus\b|\bGet-MpPreference\b", re.I),
     "T1518.001", "Windows Defender status query", None),
    (re.compile(r"\bwmic(?:\.exe)?\s+/namespace:\\\\root\\\\SecurityCenter2\s+path\s+AntiVirusProduct", re.I),
     "T1518.001", "Antivirus product discovery via WMI", None),

    # ── T1124: System Time Discovery ────────────────────────────────────
    (re.compile(r"\bw32tm(?:\.exe)?\s+/(?:query|tz|stripchart)", re.I),
     "T1124", "System time discovery via w32tm", None),
    (re.compile(r"\bnet(?:1)?(?:\.exe)?\s+time\b", re.I),
     "T1124", "System time discovery via net time", None),
    (re.compile(r"\bGet-Date\b|\b\[DateTime\]::(?:Now|UtcNow)\b", re.I),
     "T1124", "System time discovery via PowerShell", None),

    # ── T1120: Peripheral Device Discovery ──────────────────────────────
    (re.compile(r"\bfsutil(?:\.exe)?\s+(?:fsinfo|volume)\s+", re.I),
     "T1120", "Peripheral/volume discovery via fsutil", None),
    (re.compile(r"\bGet-PnpDevice\b|\bGet-WmiObject\s+Win32_PnPEntity\b", re.I),
     "T1120", "Peripheral device enumeration via PowerShell", None),
    (re.compile(r"\bwmic(?:\.exe)?\s+(?:diskdrive|logicaldisk)\s+(?:list|get)", re.I),
     "T1120", "Disk/device enumeration via WMIC", None),

    # ── T1614: System Location Discovery ────────────────────────────────
    (re.compile(r"\bGet-WinHomeLocation\b|\bGet-WinSystemLocale\b", re.I),
     "T1614", "System location discovery via PowerShell", None),
    (re.compile(r"\btzutil(?:\.exe)?\s+/(?:g|l|s)", re.I),
     "T1614", "Timezone enumeration via tzutil", None),
    (re.compile(r"\bGet-TimeZone\b", re.I),
     "T1614", "Timezone discovery via PowerShell", None),

    # ── T1040: Network Sniffing ─────────────────────────────────────────
    (re.compile(r"\bnetsh(?:\.exe)?\s+trace\s+start\b", re.I),
     "T1040", "Network capture via netsh trace", None),
    (re.compile(r"\bpktmon(?:\.exe)?\s+(?:start|filter\s+add)", re.I),
     "T1040", "Network sniffing via pktmon", None),
    (re.compile(r"\b(?:tshark|dumpcap|windump|tcpdump)(?:\.exe)?\s+.*-(?:i|w)\s+", re.I),
     "T1040", "Network packet capture tool", None),

    # ── T1564.001: Hidden Files and Directories ─────────────────────────
    (re.compile(r"\battrib(?:\.exe)?\s+\+[hH]\s+", re.I),
     "T1564.001", "File hidden via attrib +h", None),
    (re.compile(r"\bSet-ItemProperty\s+.*Attributes.*Hidden\b", re.I),
     "T1564.001", "File hidden via PowerShell", None),

    # ── T1564.004: NTFS Alternate Data Streams ──────────────────────────
    (re.compile(r"\btype\s+.*>\s*\S+:\S+", re.I),
     "T1564.004", "Data written to NTFS alternate data stream", None),
    (re.compile(r"\bSet-Content\s+.*-Stream\s+", re.I),
     "T1564.004", "NTFS ADS written via PowerShell", None),
    (re.compile(r"\bstreams(?:\.exe|64\.exe)?\s+", re.I),
     "T1564.004", "Sysinternals Streams ADS enumeration", None),

    # ── T1222: File and Directory Permissions Modification ──────────────
    (re.compile(r"\bicacls(?:\.exe)?\s+.*(?:/grant|/deny|/remove|/inheritance)", re.I),
     "T1222.001", "File permissions modified via icacls", None),
    (re.compile(r"\btakeown(?:\.exe)?\s+/", re.I),
     "T1222.001", "File ownership taken via takeown", None),
    (re.compile(r"\bcacls(?:\.exe)?\s+.*(?:/[egtpcd])", re.I),
     "T1222.001", "File permissions modified via cacls", None),
    (re.compile(r"\bSet-Acl\b|\bGet-Acl\b.*\bSet-Acl\b", re.I),
     "T1222.001", "File ACL modified via PowerShell", None),

    # ── T1552.001: Credentials in Files ─────────────────────────────────
    (re.compile(r"\bfindstr(?:\.exe)?\s+/si\s+(?:password|passwd|credential|secret|token)", re.I),
     "T1552.001", "Credential search in files via findstr", None),
    (re.compile(r"\bSelect-String\s+.*(?:password|passwd|credential|secret|token|apikey)", re.I),
     "T1552.001", "Credential search in files via PowerShell", None),
    (re.compile(r"\bdir\s+.*(?:\.config|web\.config|appsettings\.json|\.env)\b", re.I),
     "T1552.001", "Configuration file enumeration for credentials", None),

    # ── T1560.001: Archive Collected Data via Utility ────────────────────
    (re.compile(r"\bcompact(?:\.exe)?\s+/c\s+", re.I),
     "T1560.001", "Data compressed via compact.exe", None),
    (re.compile(r"\bmakecab(?:\.exe)?\s+", re.I),
     "T1560.001", "Data archived via makecab", None),
    (re.compile(r"\brar(?:\.exe)?\s+a\b", re.I),
     "T1560.001", "Data archived via rar", None),

    # ── T1132: Data Encoding ────────────────────────────────────────────
    (re.compile(r"\bcertutil(?:\.exe)?\s+.*(?:-|/)encode\b", re.I),
     "T1132.001", "Data encoded via certutil (base64)", None),
    (re.compile(r"\b\[Convert\]::ToBase64String\b", re.I),
     "T1132.001", "Data encoded via PowerShell Base64", None),

    # ── T1557: Adversary-in-the-Middle / LLMNR Poisoning ────────────────
    (re.compile(r"\b(?:responder|Responder)(?:\.py|\.exe)?\s+.*-I\s+", re.I),
     "T1557.001", "LLMNR/NBT-NS poisoning via Responder", None),
    (re.compile(r"\bInveigh\b.*(?:Start|Invoke)", re.I),
     "T1557.001", "LLMNR/NBT-NS poisoning via Inveigh", None),
    (re.compile(r"\bmitm6(?:\.py)?\s+", re.I),
     "T1557.001", "IPv6 DNS poisoning via mitm6", None),

    # ── T1110: Brute Force ──────────────────────────────────────────────
    (re.compile(r"\bhydra(?:\.exe)?\s+.*(?:-l|-L|-P|-C)\s+", re.I),
     "T1110", "Brute force attack via Hydra", None),
    (re.compile(r"\bcrackmapexec(?:\.exe)?\s+", re.I),
     "T1110", "Credential brute-force/spray via CrackMapExec", None),
    (re.compile(r"\b(?:ncrack|medusa|patator)(?:\.exe)?\s+", re.I),
     "T1110", "Network brute force tool detected", None),
    (re.compile(r"\bInvoke-SprayPassword\b|\bSpray-Passwords\b", re.I),
     "T1110.003", "Password spray via PowerShell", None),

    # ═══════════════════════════════════════════════════════════════════════
    # MITRE Coverage Expansion #3 — 20+ new base techniques (80+ target)
    # Focuses on: Exfiltration, Collection, C2, Credential Access,
    # Persistence, Execution, Impact, Defense Evasion
    # ═══════════════════════════════════════════════════════════════════════

    # ── T1005: Data from Local System ───────────────────────────────────
    (re.compile(r"\bcopy\s+.*(?:SAM|SYSTEM|SECURITY|NTDS\.dit)\b", re.I),
     "T1005", "Sensitive system file copy (SAM/NTDS)", None),
    (re.compile(r"\besentutl(?:\.exe)?\s+.*(?:/y|copy|NTDS)", re.I),
     "T1005", "Database file extraction via esentutl", None),
    (re.compile(r"\bGet-Content\s+.*(?:\\SAM|\\SYSTEM|\\SECURITY|NTDS\.dit)", re.I),
     "T1005", "Sensitive system file read via PowerShell", None),

    # ── T1020: Automated Exfiltration ───────────────────────────────────
    (re.compile(r"\bschtasks(?:\.exe)?\s+/create\s+.*(?:ftp|curl|scp|rclone|mega)", re.I),
     "T1020", "Scheduled exfiltration task creation", None),
    (re.compile(r"\brclone(?:\.exe)?\s+(?:copy|sync|move)\s+", re.I),
     "T1020", "Automated cloud sync via rclone (exfiltration)", None),

    # ── T1041: Exfiltration Over C2 Channel ─────────────────────────────
    (re.compile(r"\bcurl(?:\.exe)?\s+.*(?:-T\s+|-d\s+@|--data-binary\s+@|--upload-file)\s*\S+", re.I),
     "T1041", "Data upload via curl (C2 exfiltration)", None),
    (re.compile(r"\bwget(?:\.exe)?\s+.*--post-file\s+", re.I),
     "T1041", "Data upload via wget (C2 exfiltration)", None),
    (re.compile(r"\bInvoke-RestMethod\s+.*-Method\s+(?:Post|Put)\s+.*-InFile\s+", re.I),
     "T1041", "Data upload via PowerShell REST (C2 exfiltration)", None),

    # ── T1046: Network Service Discovery ────────────────────────────────
    (re.compile(r"\bnmap(?:\.exe)?\s+", re.I),
     "T1046", "Port scan via nmap", None),
    (re.compile(r"\bTest-NetConnection\b.*-Port\b", re.I),
     "T1046", "Port scan via PowerShell Test-NetConnection", None),
    (re.compile(r"\bmasscan(?:\.exe)?\s+", re.I),
     "T1046", "Mass port scan via masscan", None),
    (re.compile(r"\b(?:1\.\.(?:65535|1024|255)|ForEach.*Test-NetConnection.*-Port)", re.I),
     "T1046", "PowerShell port sweep loop", None),

    # ── T1056.001: Input Capture - Keylogging ───────────────────────────
    (re.compile(r"\bSetWindowsHookEx\b.*(?:WH_KEYBOARD|13)\b", re.I),
     "T1056.001", "Keyboard hook installation (keylogger)", None),
    (re.compile(r"\bGetAsyncKeyState\b|\bGetKeyState\b.*(?:loop|while|for)", re.I),
     "T1056.001", "Keystroke polling via Win32 API", None),
    (re.compile(r"\b(?:keylog|KeyLogger|LogKeys|Get-Keystrokes)\b", re.I),
     "T1056.001", "Keylogger tool detected", None),

    # ── T1071: Application Layer Protocol ───────────────────────────────
    (re.compile(r"\bInvoke-WebRequest\s+.*(?:\.onion|\.i2p)\b", re.I),
     "T1071.001", "Communication over Tor/I2P network", None),
    (re.compile(r"\b(?:ssh|plink)(?:\.exe)?\s+.*-R\s+\d+:", re.I),
     "T1071", "Reverse SSH tunnel for C2 communication", None),
    (re.compile(r"\bchisel(?:\.exe)?\s+(?:client|server)\b", re.I),
     "T1071", "Chisel tunnel for C2 communication", None),

    # ── T1102: Web Service (C2 via legitimate services) ─────────────────
    (re.compile(r"\bhttps?://(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.co)/", re.I),
     "T1102", "Communication with paste service (C2 channel)", None),
    (re.compile(r"\bhttps?://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)/", re.I),
     "T1102", "Communication via Discord/Slack webhook (C2)", None),
    (re.compile(r"\bhttps?://api\.telegram\.org/bot", re.I),
     "T1102", "Communication via Telegram Bot API (C2)", None),
    (re.compile(r"\bngrok(?:\.exe)?\s+(?:tcp|http|start)\b", re.I),
     "T1102", "Ngrok tunnel for C2/exfiltration", None),

    # ── T1106: Native API ───────────────────────────────────────────────
    (re.compile(r"\bNtCreateThread(?:Ex)?\b|\bNtAllocateVirtualMemory\b|\bNtWriteVirtualMemory\b", re.I),
     "T1106", "Direct NT syscall for code execution", None),
    (re.compile(r"\bGetProcAddress\b.*(?:ntdll|kernel32).*\b(?:NtCreate|NtOpen|NtWrite|NtRead|NtAlloc)", re.I),
     "T1106", "Dynamic resolution of NT API (evasion)", None),
    (re.compile(r"\bAdd-Type\s+-MemberDefinition\s+.*DllImport.*(?:ntdll|kernel32)", re.I),
     "T1106", "PowerShell P/Invoke for native API access", None),

    # ── T1111: Multi-Factor Authentication Interception ─────────────────
    (re.compile(r"\b(?:evilginx2?|modlishka|muraena|gophish)(?:\.exe)?\b", re.I),
     "T1111", "MFA interception/phishing proxy tool", None),
    (re.compile(r"\b(?:credsniper|king-phisher|SocialFish)\b", re.I),
     "T1111", "Credential/MFA phishing framework", None),

    # ── T1137: Office Application Startup ───────────────────────────────
    (re.compile(r"\bcopy\s+.*(?:XLSTART|STARTUP|Word\\STARTUP|Excel\\XLSTART)\\", re.I),
     "T1137", "File planted in Office startup folder", None),
    (re.compile(r"\breg(?:\.exe)?\s+add\s+.*Office\\.*\\(?:Security|Addins|Common)", re.I),
     "T1137", "Office startup registry key modified", None),
    (re.compile(r"\.(?:wll|xll|xlam|dotm|ppam)\b.*(?:XLSTART|STARTUP|Addins)", re.I),
     "T1137", "Office add-in planted in startup path", None),

    # ── T1176: Browser Extensions ───────────────────────────────────────
    (re.compile(r"\b(?:chrome|msedge)(?:\.exe)?\s+.*--load-extension\b", re.I),
     "T1176", "Browser loaded with sideloaded extension", None),
    (re.compile(r"\\(?:Chrome|Edge)\\User Data\\.*\\Extensions\\[a-z]{32}", re.I),
     "T1176", "Browser extension path access", None),

    # ── T1189: Drive-by Compromise ──────────────────────────────────────
    (re.compile(r"\b(?:wscript|cscript)(?:\.exe)?\s+.*(?:\\Temp\\|\\Downloads\\|\\AppData\\).*\.(?:js|vbs|wsf)\b", re.I),
     "T1189", "Script execution from temp/download folder (drive-by)", None),
    (re.compile(r"\b(?:iexplore|msedge|chrome|firefox)(?:\.exe)?.*\.(?:hta|jnlp|application)\b", re.I),
     "T1189", "Browser opening executable content (drive-by)", None),

    # ── T1204: User Execution ───────────────────────────────────────────
    (re.compile(r"\b(?:cmd|powershell|wscript|cscript)(?:\.exe)?\s+.*\\(?:Downloads|Desktop|Temp)\\.*\.(?:bat|cmd|ps1|vbs|js|exe|scr|pif)\b", re.I),
     "T1204.002", "User executing file from download/desktop path", None),
    (re.compile(r"\b(?:mshta|rundll32|regsvr32)(?:\.exe)?\s+.*\\(?:Downloads|Temp)\\", re.I),
     "T1204.002", "LOLBin executing from user download folder", None),

    # ── T1482: Domain Trust Discovery ───────────────────────────────────
    (re.compile(r"\bnltest(?:\.exe)?\s+/domain_trusts", re.I),
     "T1482", "Domain trust discovery via nltest", None),
    (re.compile(r"\bGet-ADTrust\b|\bGet-DomainTrust\b|\b(?:dsquery|csvde)(?:\.exe)?\s+.*trustedDomain", re.I),
     "T1482", "Domain trust enumeration via AD tools", None),
    (re.compile(r"\b(?:Get-ForestTrust|Get-NetForestDomain|Get-DomainTrustMapping)\b", re.I),
     "T1482", "Domain/forest trust mapping via PowerView", None),

    # ── T1484: Domain Policy Modification ───────────────────────────────
    (re.compile(r"\bNew-GPO\b|\bSet-GPRegistryValue\b|\bNew-GPLink\b", re.I),
     "T1484.001", "Group Policy modification via PowerShell", None),
    (re.compile(r"\bgpscript(?:\.exe)?\b|\bImport-GPO\b", re.I),
     "T1484.001", "GPO import or script execution", None),

    # ── T1485: Data Destruction ─────────────────────────────────────────
    (re.compile(r"\b(?:sdelete|eraser|shred)(?:\.exe|64\.exe)?\s+", re.I),
     "T1485", "Secure file deletion tool (data destruction)", None),
    (re.compile(r"\bRemove-Item\s+.*-Recurse\s+.*-Force\b", re.I),
     "T1485", "Recursive forced file deletion via PowerShell", None),
    (re.compile(r"\brd\s+/s\s+/q\s+(?:C:\\|D:\\|\\\\)", re.I),
     "T1485", "Recursive directory deletion (data destruction)", None),

    # ── T1496: Resource Hijacking ───────────────────────────────────────
    (re.compile(r"\b(?:xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|minerd|t-rex)(?:\.exe)?\b", re.I),
     "T1496", "Cryptocurrency miner detected", None),
    (re.compile(r"\bstratum\+tcp://|\bstratum\+ssl://", re.I),
     "T1496", "Stratum mining pool connection", None),
    (re.compile(r"\b(?:monero|bitcoin|ethereum|zcash).*(?:wallet|pool|mining|hashrate)", re.I),
     "T1496", "Crypto mining terminology in command line", None),

    # ── T1550: Use Alternate Authentication Material ────────────────────
    (re.compile(r"\bsekurlsa::pth\b|\b(?:Invoke-)?Pass(?:The|-)Hash\b", re.I),
     "T1550.002", "Pass-the-Hash attack", None),
    (re.compile(r"\bkerberos::ptt\b|\b(?:Invoke-)?Pass(?:The|-)Ticket\b|\bRubeus\b.*\bptt\b", re.I),
     "T1550.003", "Pass-the-Ticket attack", None),
    (re.compile(r"\b(?:Invoke-)?OverPass(?:The|-)Hash\b|\basktgt\b.*(?:/rc4|/aes256|/ntlm)", re.I),
     "T1550.002", "Overpass-the-Hash / NTLM-to-Kerberos", None),

    # ── T1553: Subvert Trust Controls ───────────────────────────────────
    (re.compile(r"\bcertutil(?:\.exe)?\s+(?:-|/)addstore\s+(?:root|trustedpublisher)", re.I),
     "T1553.004", "Root certificate installed via certutil", None),
    (re.compile(r"\bImport-Certificate\b.*(?:Root|TrustedPublisher)", re.I),
     "T1553.004", "Root certificate installed via PowerShell", None),
    (re.compile(r"\bSet-AuthenticodeSignature\b|\bsigntool(?:\.exe)?\s+sign\b", re.I),
     "T1553.002", "Code signing operation (trust subversion)", None),

    # ── T1558: Steal or Forge Kerberos Tickets ──────────────────────────
    (re.compile(r"\bRubeus(?:\.exe)?\s+(?:kerberoast|asreproast|harvest|tgtdeleg|renew|brute|s4u)\b", re.I),
     "T1558", "Kerberos attack via Rubeus", None),
    (re.compile(r"\b(?:Invoke-Kerberoast|Get-DomainSPNTicket)\b", re.I),
     "T1558.003", "Kerberoasting via PowerShell", None),
    (re.compile(r"\.kirbi\b|\.ccache\b|ticket\.(?:b64|bin)\b", re.I),
     "T1558", "Kerberos ticket file detected", None),
    (re.compile(r"\bkerberos::(?:golden|silver|list|purge|tgt)\b", re.I),
     "T1558.001", "Golden/Silver ticket via Mimikatz kerberos module", None),

    # ── T1059.003: Windows Command Shell ────────────────────────────────
    (re.compile(r"\bcmd(?:\.exe)?\s+/c\s+.*(?:echo|type|more)\s+.*\|\s*(?:cmd|powershell)", re.I),
     "T1059.003", "Piped command execution via cmd.exe", None),

    # ── T1059.005: Visual Basic ─────────────────────────────────────────
    (re.compile(r"\b(?:wscript|cscript)(?:\.exe)?\s+.*\.vbs\b", re.I),
     "T1059.005", "VBScript execution via Windows Script Host", None),

    # ── T1059.007: JavaScript ───────────────────────────────────────────
    (re.compile(r"\b(?:wscript|cscript)(?:\.exe)?\s+.*\.(?:js|jse|wsf)\b", re.I),
     "T1059.007", "JavaScript execution via Windows Script Host", None),

    # ── T1574: Hijack Execution Flow ────────────────────────────────────
    (re.compile(r"\breg(?:\.exe)?\s+add\s+.*(?:Image File Execution Options|IFEO)\\", re.I),
     "T1574.012", "Image File Execution Options debugger set", None),
    (re.compile(r"\breg(?:\.exe)?\s+add\s+.*\\Environment\\.*Path\b", re.I),
     "T1574.007", "PATH environment variable modification for DLL hijack", None),

    # ── T1027.010: Command Obfuscation ──────────────────────────────────
    (re.compile(r"\^.\^.\^.\^.\^.", re.I),
     "T1027.010", "Caret obfuscation in command line", None),
    (re.compile(r"\bset\s+\w+=.\s*&&.*%\w+%.*%\w+%", re.I),
     "T1027.010", "Environment variable concatenation obfuscation", None),

    # ── T1546.001: Change Default File Association ──────────────────────
    (re.compile(r"\bassoc\s+\.(?:exe|bat|cmd|ps1|vbs|js)=", re.I),
     "T1546.001", "File association hijack via assoc", None),
    (re.compile(r"\bftype\s+\w+=.*(?:cmd|powershell|wscript)", re.I),
     "T1546.001", "File type handler hijack via ftype", None),

    # ── T1546.015: Component Object Model Hijacking ─────────────────────
    (re.compile(r"\breg(?:\.exe)?\s+add\s+.*\\CLSID\\.*\\InprocServer32\b", re.I),
     "T1546.015", "COM object hijack via InprocServer32 registry", None),

    # ── T1003.003: NTDS.dit extraction ──────────────────────────────────
    (re.compile(r"\bntdsutil(?:\.exe)?\s+.*(?:ifm|\"activate instance ntds\")", re.I),
     "T1003.003", "Active Directory database extraction via ntdsutil", None),

    # ── T1048.002: Exfiltration Over Asymmetric Encrypted Protocol ──────
    (re.compile(r"\bscp(?:\.exe)?\s+.*@.*:", re.I),
     "T1048.002", "File transfer via SCP (encrypted exfiltration)", None),
    (re.compile(r"\bsftp(?:\.exe)?\s+.*@", re.I),
     "T1048.002", "File transfer via SFTP (encrypted exfiltration)", None),
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
    """Check if this alert came from a Sysmon, Windows Event Log, or PowerShell feed.

    As of Phase 2 the translator also runs on Windows Security Event Log events
    (export_secevt.ps1) and PowerShell Script Block Log events (export_psbl.ps1),
    because those also carry structured command-line data the MITRE patterns
    and event-ID fork logic can enrich.
    """
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
    # Field markers that indicate endpoint telemetry source
    has_endpoint_markers = bool(
        raw_alert.get("_sysmonEventId")
        or raw_alert.get("_sourceEventId")
        or raw_alert.get("_winEventId")
        or (raw_alert.get("process") and raw_alert.get("commandLine"))
    )
    accepted_source_keywords = ("sysmon", "windowseventlog", "windows event log",
                                "powershell", "security-auditing")
    return (
        any(kw in source_name for kw in accepted_source_keywords)
        or any(kw in source_tool for kw in accepted_source_keywords)
        or has_endpoint_markers
    )


# ---------------------------------------------------------------------------
# Event-ID fork: direct detection based on the numeric EventID carried by
# the source tool. Runs after the regex pattern pass. This lets us detect
# events that have no command-line text (e.g., Windows Security Event Log
# 4720 account creation, Sysmon EID 10 LSASS access, EIDs 19/20/21 WMI
# persistence) by matching on their EventID alone.
# ---------------------------------------------------------------------------

def _translate_by_sysmon_event_id(raw_alert: dict[str, Any]) -> tuple[int, set[str]]:
    """Inspect `_sourceEventId` / `_sysmonEventId` and set fields directly.

    Returns (fields_added, techniques_found_set).
    """
    added = 0
    techniques: set[str] = set()

    # Pull the event ID from multiple possible field names
    eid_raw = (
        raw_alert.get("_sourceEventId")
        or raw_alert.get("_sysmonEventId")
        or raw_alert.get("_winEventId")
    )
    try:
        eid = int(eid_raw) if eid_raw is not None else None
    except (ValueError, TypeError):
        eid = None

    if eid is None:
        return 0, techniques

    # ── Sysmon EID 10: Process Access (primarily LSASS) ──────────────────
    if eid == 10:
        target = str(raw_alert.get("_targetImage") or raw_alert.get("TargetImage") or "").lower()
        if "lsass.exe" in target:
            if raw_alert.get("_lsassAccess") is not True:
                raw_alert["_lsassAccess"] = True
                added += 1
            techniques.add("T1003.001")
            sysmon_eid_fork_hits.labels(event_id="10", branch="lsass_access").inc()
            _log.debug("sysmon_translator: EID 10 → _lsassAccess (T1003.001)")

    # ── Sysmon EIDs 17/18: Named Pipe Create/Connect ─────────────────────
    elif eid in (17, 18):
        pipe = str(raw_alert.get("_pipeName") or raw_alert.get("PipeName") or "")
        if pipe:
            if raw_alert.get("_namedPipeActivity") is not True:
                raw_alert["_namedPipeActivity"] = True
                added += 1
            sysmon_eid_fork_hits.labels(
                event_id=str(eid), branch="named_pipe_activity"
            ).inc()
            # Known lateral movement / C2 pipe patterns
            lm_pipes = ["psexesvc", "paexec", "remcom", "csexec", "atexec",
                        "crackmapexec", "mojo", "admin$", "ipc$"]
            pipe_lower = pipe.lower()
            if any(p in pipe_lower for p in lm_pipes):
                if raw_alert.get("_lateralMovementPipe") is not True:
                    raw_alert["_lateralMovementPipe"] = True
                    added += 1
                techniques.add("T1570")
                techniques.add("T1021.002")
                sysmon_eid_fork_hits.labels(
                    event_id=str(eid), branch="lateral_movement_pipe"
                ).inc()

    # ── Sysmon EIDs 19/20/21: WMI Event Filter/Consumer/Binding ─────────
    elif eid in (19, 20, 21):
        # These events are extremely rare legitimately. Fire immediately.
        if raw_alert.get("_wmiPersistence") is not True:
            raw_alert["_wmiPersistence"] = True
            added += 1
        techniques.add("T1546.003")
        sysmon_eid_fork_hits.labels(event_id=str(eid), branch="wmi_persistence").inc()
        _log.debug("sysmon_translator: EID %d → _wmiPersistence (T1546.003)", eid)

    # ── Windows Security Event 1102: Audit Log Cleared ──────────────────
    elif eid == 1102:
        if raw_alert.get("_logCleared") is not True:
            raw_alert["_logCleared"] = True
            added += 1
        techniques.add("T1070.001")
        sysmon_eid_fork_hits.labels(event_id="1102", branch="log_cleared").inc()

    # ── Windows Security Event 4720: User Account Created ───────────────
    elif eid == 4720:
        if raw_alert.get("_accountCreated") is not True:
            raw_alert["_accountCreated"] = True
            added += 1
        techniques.add("T1136.001")
        sysmon_eid_fork_hits.labels(event_id="4720", branch="account_created").inc()

    # ── Windows Security Events 4728/4732: Added to Privileged Group ────
    elif eid in (4728, 4732):
        target_group = str(raw_alert.get("_targetGroup") or raw_alert.get("TargetGroupName") or "").lower()
        privileged_groups = ("administrators", "domain admins", "enterprise admins",
                             "schema admins", "backup operators", "account operators")
        if any(g in target_group for g in privileged_groups):
            if raw_alert.get("_privilegeEscalation") is not True:
                raw_alert["_privilegeEscalation"] = True
                added += 1
            techniques.add("T1098")
            sysmon_eid_fork_hits.labels(
                event_id=str(eid), branch="privilege_escalation"
            ).inc()

    # ── Windows Security Event 4672: Special Privileges Assigned ────────
    elif eid == 4672:
        if raw_alert.get("_privilegeEscalation") is not True:
            raw_alert["_privilegeEscalation"] = True
            added += 1
        sysmon_eid_fork_hits.labels(event_id="4672", branch="priv_assigned").inc()
        # Not a full technique hit (4672 can be noisy) — no MITRE add

    return added, techniques


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
    tenant_label = str(raw_alert.get("_tenantId") or raw_alert.get("tenantId") or "unknown")
    if combined:
        for pattern, technique, label, field_name in _MITRE_PATTERNS:
            if pattern.search(combined):
                techniques_found.add(technique)
                sysmon_pattern_hits.labels(
                    pattern=technique, tenant=tenant_label
                ).inc()
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

    # ── Event-ID fork (Phase 2.4): detect events that have no command line ──
    # e.g. Windows Security Event Log 4720 (account created),
    # Sysmon EID 10 (process access / LSASS), EIDs 19/20/21 (WMI persistence).
    _eid_added, _eid_techniques = _translate_by_sysmon_event_id(raw_alert)
    added += _eid_added
    techniques_found |= _eid_techniques

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

    # ── PowerShell content classification ─────────────────────────────────
    # Runs on ALL PowerShell cases (even if MITRE matched) to add granular
    # signals based on WHAT the script does. These create score spread —
    # a script that writes files scores differently from one that reads them.
    if combined and not techniques_found:
        _classify_powershell_content(raw_alert, combined)

    # ── Benign PowerShell classifier ────────────────────────────────────
    # Only runs when NO MITRE pattern matched. Identifies known-safe scripts
    # (module imports, Get-* cmdlets, DSC, WMI queries) so the scoring pipeline
    # can push them DOWN with a negative-weight signal. MITRE always wins —
    # a script that matches both a MITRE technique AND a benign pattern gets
    # the attack signal, not the benign classification.
    if not techniques_found and combined:
        benign_reason = _classify_benign_powershell(combined)
        if benign_reason and raw_alert.get("_benignPowerShell") is not True:
            raw_alert["_benignPowerShell"] = True
            raw_alert["_benignPowerShellReason"] = benign_reason
            added += 2
            _log.debug(
                "sysmon_translator: benign PowerShell classified: %s",
                benign_reason,
            )

    return added


# ---------------------------------------------------------------------------
# PowerShell content classification — granular behavioral signals
# ---------------------------------------------------------------------------
# These fire based on WHAT the script does (not just that it exists).
# Each one sets a boolean flag on raw_alert that the signal extractor reads.

_PS_CONTENT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Registry access (read or write)
    (re.compile(r"\b(?:Get-ItemProperty|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\s+.*(?:HKLM|HKCU|HKCR|Registry)", re.I),
     "_psRegistryAccess"),
    (re.compile(r"\breg(?:\.exe)?\s+(?:add|delete|query)\s+HK", re.I),
     "_psRegistryAccess"),

    # File write operations
    (re.compile(r"\b(?:Set-Content|Add-Content|Out-File|New-Item\s+.*-ItemType\s+File)\b", re.I),
     "_psFileWrite"),
    (re.compile(r"\b(?:\[IO\.File\]::Write|\[System\.IO\.File\]::Write|StreamWriter)", re.I),
     "_psFileWrite"),

    # Network calls
    (re.compile(r"\b(?:Invoke-WebRequest|Invoke-RestMethod|System\.Net\.WebClient|Net\.Sockets|HttpClient|wget|curl)\b", re.I),
     "_psNetworkCall"),
    (re.compile(r"\b(?:Test-NetConnection|New-Object\s+.*Net\.)", re.I),
     "_psNetworkCall"),

    # Process spawning
    (re.compile(r"\b(?:Start-Process|Invoke-Expression|Invoke-Command|iex\s*\(|& (?:cmd|powershell|wscript|cscript))", re.I),
     "_psProcessSpawn"),

    # Credential access
    (re.compile(r"\b(?:Get-Credential|ConvertTo-SecureString|ConvertFrom-SecureString|PSCredential|CredentialCache)", re.I),
     "_psCredentialAccess"),

    # COM object usage
    (re.compile(r"\bNew-Object\s+.*-ComObject\b", re.I),
     "_psComObject"),

    # WMI method calls (not just queries — actual method invocations)
    (re.compile(r"\b(?:Invoke-WmiMethod|Invoke-CimMethod|Set-WmiInstance|Set-CimInstance)\b", re.I),
     "_psWmiCall"),

    # Service manipulation
    (re.compile(r"\b(?:Set-Service|New-Service|Remove-Service|Restart-Service|Stop-Service)\b", re.I),
     "_psServiceManipulation"),

    # Event log access
    (re.compile(r"\b(?:Get-WinEvent|Get-EventLog|Clear-EventLog|wevtutil)\b", re.I),
     "_psEventLogAccess"),

    # Base64 usage (not flagged as encoded command by MITRE patterns)
    (re.compile(r"\b(?:FromBase64String|ToBase64String|\[Convert\]::FromBase64)\b", re.I),
     "_psBase64Usage"),
]


def _classify_powershell_content(raw_alert: dict[str, Any], combined: str) -> None:
    """Set boolean flags on raw_alert based on PowerShell script content.

    Each flag drives a signal in extract_powershell_execution with its own
    weight and tier, creating score spread across different script behaviors.
    """
    for pattern, field_name in _PS_CONTENT_PATTERNS:
        if raw_alert.get(field_name) is True:
            continue  # already set (idempotent)
        if pattern.search(combined):
            raw_alert[field_name] = True


# ---------------------------------------------------------------------------
# Benign PowerShell classification
# ---------------------------------------------------------------------------

_BENIGN_POWERSHELL_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ── Vigilis self-monitoring (own exporter scripts logged by PSBL) ────
    (re.compile(r"\bexport_sysmon\b|\bexport_psbl\b|\bexport_secevt\b|\bexport_state\b", re.I),
     "Vigilis exporter script (self-monitoring)"),
    (re.compile(r"\bVigilisUrl\b|\bSet-Content\s+\$StateFile\b|\bConvertTo-Json\s+-Compress\b", re.I),
     "Vigilis exporter fragment"),
    (re.compile(r"\bInvoke-RestMethod\s+.*api/v1/cases\b|\bapi/v1/exporter/heartbeat\b", re.I),
     "Vigilis API call (self-monitoring)"),

    # ── PowerShell internals / automatic variables ──────────────────────
    (re.compile(r"^\s*\$global:\?\s*$", re.I),
     "PowerShell automatic variable"),
    (re.compile(r"^\s*\{\s*\$_\s*[-\.]\w+\s*\}\s*$", re.I),
     "Simple script block expression"),
    (re.compile(r"^\s*\{\s*\[char\]\$_\s*\}\s*$", re.I),
     "Character conversion block"),
    (re.compile(r"^\s*\{\s*\$_\s+-in\s+[\d,\s]+\}\s*$", re.I),
     "Numeric filter expression"),

    # ── Module / assembly / alias setup ─────────────────────────────────
    (re.compile(r"(?:^|\n)\s*(?:import-module|using\s+module|using\s+namespace)\s", re.I),
     "Module import statement"),
    (re.compile(r"(?:^|\n)\s*Set-Alias\s+-Name\s+\w+\s+-Value\s+\w+", re.I),
     "Alias definition"),
    (re.compile(r"(?:^|\n)\s*#\s*(?:requires|region|endregion)\b", re.I),
     "Script metadata directive"),
    (re.compile(r"^\s*#[^!]", re.I),
     "Comment-only script block"),

    # ── Pure read-only cmdlets (no side effects) ────────────────────────
    (re.compile(r"(?:^|\n)\s*(?:Get-|Select-|Where-Object|ForEach-Object|Format-|Out-|Write-(?:Host|Output|Verbose|Debug|Warning))\b", re.I),
     "Read-only cmdlet"),

    # ── Variable assignment / string interpolation ──────────────────────
    (re.compile(r"^\s*\$\w+\s*=\s*[\"']", re.I),
     "Simple variable assignment"),

    # ── Windows Update / servicing ──────────────────────────────────────
    (re.compile(r"\bWindowsUpdateClient\b|\bWudfHost\b|\bPSWindowsUpdate\b", re.I),
     "Windows Update activity"),

    # ── DSC (Desired State Configuration) ───────────────────────────────
    (re.compile(r"\bConfiguration\s+\w+\s*\{|\bStart-DscConfiguration\b|\bTest-DscConfiguration\b", re.I),
     "DSC configuration"),

    # ── Package management ──────────────────────────────────────────────
    (re.compile(r"(?:^|\n)\s*(?:Install-Module|Find-Module|Update-Module|Get-Package|Register-PSRepository)\b", re.I),
     "Package management cmdlet"),

    # ── Prompt / profile / ISE ──────────────────────────────────────────
    (re.compile(r"(?:^|\n)\s*(?:function\s+prompt\b|\$profile\b)|Microsoft\.PowerShell_profile\.ps1", re.I),
     "PowerShell profile/prompt"),

    # ── CIM/WMI read-only queries ───────────────────────────────────────
    (re.compile(r"(?:^|\n)\s*(?:Get-CimInstance|Get-WmiObject)\s+(?:Win32_|CIM_|MSFT_)", re.I),
     "WMI/CIM inventory query"),

    # ── Compatibility telemetry ─────────────────────────────────────────
    (re.compile(r"\bCompatTelRunner\b|\bSoftwareInventoryLogging\b|\bCeipData\b", re.I),
     "Compatibility/telemetry collection"),

    # ── Script signing / certificate ────────────────────────────────────
    (re.compile(r"\bGet-AuthenticodeSignature\b|\bSet-AuthenticodeSignature\b", re.I),
     "Script signing operation"),

    # ── Admin health-check cmdlets ──────────────────────────────────────
    (re.compile(r"(?:^|\n)\s*(?:Test-Connection|Test-NetConnection|Resolve-DnsName|Get-Service|Get-EventLog|Get-Counter|Get-Process|Get-ChildItem|Get-Item|Get-Content|Get-Date|Get-Host|Get-Member|Get-Variable|Get-Command|Get-Help)\b", re.I),
     "Admin/diagnostic cmdlet"),

    # ── Type accelerator / .NET access (read-only) ──────────────────────
    (re.compile(r"^\s*\[(?:System\.)?(?:IO|Net|Text|Xml|Math|Convert|Environment|DateTime)\b", re.I),
     ".NET type access"),
]


def _classify_benign_powershell(combined_text: str) -> str | None:
    """Return a reason string if the script matches a known-safe pattern.

    Returns None for unknown / suspicious scripts. Called only when no MITRE
    technique matched, so attack scripts are never classified as benign.
    """
    if not combined_text:
        return None
    for pattern, reason in _BENIGN_POWERSHELL_PATTERNS:
        if pattern.search(combined_text):
            return reason
    return None
