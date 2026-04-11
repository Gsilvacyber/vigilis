# export_psbl.ps1
# Reads PowerShell Script Block Logging events (EventID 4104) from the Windows
# Event Log and POSTs them to Vigilis as endpoint.powershellExecution alerts.
#
# The biggest win of this exporter: ScriptBlockText is the DECODED powershell
# source code, so the existing sysmon_translator._MITRE_PATTERNS regex table
# (62 patterns) matches it automatically with zero backend changes.
#
# Prerequisite: PowerShell Script Block Logging must be enabled.
# Enable via Group Policy or run this one-liner as Administrator:
#   New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
#   New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
#
# Schedule every 5 minutes via Task Scheduler.

param(
    [string]$VigilisUrl = "http://192.168.184.1:8000",
    [string]$ApiKey = "socai-demo-key-do-not-use-in-production",
    [int]$LookbackMinutes = 5,
    [int]$MaxEventsPerRun = 25,
    [string]$StateFile = "$env:TEMP\psbl_export_state.txt",
    [switch]$ShowDetails
)

$ErrorActionPreference = "Continue"

# ---- Verify Script Block Logging is enabled ----
$regKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $regKey)) {
    $regKey = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
}
$enabled = $false
if (Test-Path $regKey) {
    $val = Get-ItemProperty -Path $regKey -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    if ($val -and $val.EnableScriptBlockLogging -eq 1) { $enabled = $true }
}
if (-not $enabled) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] ERROR: PowerShell Script Block Logging is NOT enabled." -ForegroundColor Red
    Write-Host "Enable via Administrator PowerShell:" -ForegroundColor Yellow
    Write-Host "  New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force" -ForegroundColor Yellow
    Write-Host "  New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force" -ForegroundColor Yellow
    Write-Host "Then restart any open PowerShell sessions." -ForegroundColor Yellow
    exit 1
}

# ---- State management ----
if (Test-Path $StateFile) {
    try {
        $lastRun = [datetime]::Parse((Get-Content $StateFile -ErrorAction Stop))
    } catch {
        $lastRun = (Get-Date).AddMinutes(-$LookbackMinutes)
    }
} else {
    $lastRun = (Get-Date).AddMinutes(-$LookbackMinutes)
}
$currentRun = Get-Date

# ---- Block-list patterns ----
# We ship only events matching KNOWN-BAD patterns. This reduces noise to
# near-zero and catches the attacker techniques we care about. A future
# allow-list variant (baseline first 50 hashes) would give broader coverage
# at the cost of higher volume.
$suspiciousPatterns = @(
    # Encoded / obfuscated
    '[A-Za-z0-9+/=]{100,}',  # long base64 blobs
    'FromBase64String',
    '-EncodedCommand',
    '\s-enc\s',
    '\s-e\s[A-Za-z0-9+/=]{30,}',
    # Download cradles
    'DownloadString',
    'DownloadFile',
    'Net\.WebClient',
    'Invoke-WebRequest.*-OutFile',
    'Invoke-RestMethod',
    'BitsTransfer',
    # Reflection / in-memory loading
    'Invoke-Expression',
    '\bIEX\b',
    'Add-Type',
    '\[Reflection\.Assembly\]::Load',
    # Memory injection APIs
    'VirtualAlloc',
    'CreateThread',
    'WriteProcessMemory',
    'Marshal::Copy',
    'Marshal\.Copy',
    'RtlMoveMemory',
    # Credential access / AD attack tools
    'Mimikatz',
    'Invoke-Mimikatz',
    'sekurlsa::',
    'Rubeus',
    'Invoke-DCSync',
    'PowerSploit',
    'PowerView',
    'Invoke-Empire',
    # Network / reverse shell
    'Net\.Sockets\.TCPClient',
    'System\.Net\.Sockets',
    # Persistence
    'CurrentVersion\\Run',
    'schtasks',
    'Register-ScheduledTask',
    'New-Service',
    'sc\.exe\s+create',
    # Ransomware hallmarks
    'vssadmin\s+delete\s+shadows',
    'bcdedit',
    'wbadmin',
    'cipher\s+/w',
    # Defense evasion
    'Set-MpPreference',
    'Add-MpPreference.*-Exclusion',
    'Stop-Service.*WinDefend',
    'wevtutil\s+cl'
)

# Compile to regex once for speed
$combinedRegex = '(?i)' + ($suspiciousPatterns -join '|')

# ---- Query EventID 4104 ----
$filter = @{
    LogName   = "Microsoft-Windows-PowerShell/Operational"
    StartTime = $lastRun
    Id        = 4104
}

$events = @()
try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop
} catch {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] No new PSBL events since $lastRun" -ForegroundColor Gray
    } else {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] Error reading PSBL log: $($_.Exception.Message)" -ForegroundColor Red
    }
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

if ($events.Count -eq 0) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] No new PSBL events since $lastRun" -ForegroundColor Gray
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

Write-Host "[$(Get-Date -Format HH:mm:ss)] Found $($events.Count) PSBL events since $lastRun" -ForegroundColor Cyan

# ---- Filter and transform ----
$hostname = $env:COMPUTERNAME.ToLower()
$upn = "$($env:USERNAME.ToLower())@$($env:USERDOMAIN.ToLower()).local"
$sent = 0
$failed = 0
$skipped = 0
$seenHashes = @{}  # dedup within this run
$filteredEvents = @()

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $eventData = @{}
    foreach ($data in $xml.Event.EventData.Data) {
        $eventData[$data.Name] = $data.'#text'
    }

    $scriptText = $eventData.ScriptBlockText
    if (-not $scriptText) {
        $skipped++
        continue
    }

    # Apply block-list filter: only ship if matches suspicious pattern
    if ($scriptText -notmatch $combinedRegex) {
        $skipped++
        continue
    }

    # Dedup: hash the script text to avoid duplicate cases
    $sha = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($scriptText)
        )
    ).Replace("-", "").ToLower()
    if ($seenHashes.ContainsKey($sha)) {
        $skipped++
        continue
    }
    $seenHashes[$sha] = $true

    $filteredEvents += @{
        Event      = $event
        ScriptText = $scriptText
        ScriptHash = $sha
        ScriptId   = $eventData.ScriptBlockId
        Path       = $eventData.Path
    }
}

if ($filteredEvents.Count -eq 0) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] All $($events.Count) PSBL events filtered (no suspicious patterns)" -ForegroundColor Gray
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

$toSend = $filteredEvents | Select-Object -First $MaxEventsPerRun
Write-Host "[$(Get-Date -Format HH:mm:ss)] Sending $($toSend.Count) PSBL events (filtered $skipped, capped at $MaxEventsPerRun)" -ForegroundColor Cyan

# ---- POST each event ----
foreach ($item in $toSend) {
    $e = $item.Event
    $scriptText = $item.ScriptText
    # Truncate script text to 2000 chars to avoid DB bloat — the first 2000
    # characters are more than enough for pattern matching and investigation.
    $truncatedText = if ($scriptText.Length -gt 2000) { $scriptText.Substring(0, 2000) } else { $scriptText }

    $rawAlert = @{
        identity    = @{ upn = $upn }
        device      = @{ hostname = $hostname; managed = $true }
        process     = "powershell.exe"
        commandLine = $truncatedText  # MITRE patterns will match against this
        _processName = "powershell.exe"
        _scriptBlockId = $item.ScriptId
        _scriptBlockHash = $item.ScriptHash
        _scriptBlockPath = $item.Path
        _sourceEventId = 4104
        _winEventId = 4104
    }

    $preview = if ($scriptText.Length -gt 80) { $scriptText.Substring(0, 80) + "..." } else { $scriptText }
    $preview = $preview -replace "`r`n", " " -replace "`n", " "

    $payload = @{
        tenantId      = "sysmon-live"
        customer      = @{ name = "Home Lab"; environment = "prod" }
        source        = @{
            sourceSystem   = "edr"
            sourceName     = "PowerShell"
            sourceAlertId  = "psbl-$($e.RecordId)"
            sourceSeverity = "medium"
        }
        alertType     = "endpoint.powershellExecution"
        title         = "Suspicious PowerShell: $preview"
        description   = "PowerShell Script Block Logging detected suspicious pattern in ScriptBlockId $($item.ScriptId)"
        severity      = "medium"
        eventTime     = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        rawAlert      = $rawAlert
    } | ConvertTo-Json -Depth 10 -Compress

    try {
        $null = Invoke-RestMethod -Uri "$VigilisUrl/api/v1/cases" `
            -Method POST `
            -Headers @{ "X-API-Key" = $ApiKey; "Content-Type" = "application/json" } `
            -Body $payload `
            -TimeoutSec 15 `
            -ErrorAction Stop
        $sent++
        if ($ShowDetails) {
            Write-Host "  [OK] PSBL: $preview" -ForegroundColor Green
        }
    } catch {
        $failed++
        Write-Host "  [FAIL] PSBL: $($_.Exception.Message)" -ForegroundColor Yellow
        if ($failed -ge 5) {
            Write-Host "  Too many failures — aborting this run." -ForegroundColor Red
            break
        }
    }
}

$currentRun.ToString("o") | Set-Content $StateFile
Write-Host "[$(Get-Date -Format HH:mm:ss)] PSBL done: sent=$sent failed=$failed skipped=$skipped total=$($events.Count)" -ForegroundColor Green
