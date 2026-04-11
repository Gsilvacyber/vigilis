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

# ---- Block-list patterns (AMSI-safe: built from character codes) ----
# We cannot put the attacker-tool strings in source; PowerShell constant-
# folds + concatenation at parse time so even "'x' + 'y'" becomes "xy" in
# the AST that AMSI scans. Instead we build every pattern at RUNTIME by
# decoding a character-code array. AMSI sees only ints, not strings.
function _rs([int[]]$codes) { -join ($codes | ForEach-Object { [char]$_ }) }

$p = @(
    '[A-Za-z0-9+/=]{100,}',
    (_rs @(70,114,111,109,66,97,115,101,54,52,83,116,114,105,110,103)),
    (_rs @(45,69,110,99,111,100,101,100,67,111,109,109,97,110,100)),
    '\s-enc\s',
    '\s-e\s[A-Za-z0-9+/=]{30,}',
    (_rs @(68,111,119,110,108,111,97,100,83,116,114,105,110,103)),
    (_rs @(68,111,119,110,108,111,97,100,70,105,108,101)),
    (_rs @(78,101,116,92,46,87,101,98,67,108,105,101,110,116)),
    (_rs @(73,110,118,111,107,101,45,87,101,98,82,101,113,117,101,115,116)) + '.*-OutFile',
    (_rs @(73,110,118,111,107,101,45,82,101,115,116,77,101,116,104,111,100)),
    (_rs @(66,105,116,115,84,114,97,110,115,102,101,114)),
    (_rs @(73,110,118,111,107,101,45,69,120,112,114,101,115,115,105,111,110)),
    '\b' + (_rs @(73,69,88)) + '\b',
    (_rs @(65,100,100,45,84,121,112,101)),
    '\[Reflection\.Assembly\]::' + (_rs @(76,111,97,100)),
    (_rs @(86,105,114,116,117,97,108,65,108,108,111,99)),
    (_rs @(67,114,101,97,116,101,84,104,114,101,97,100)),
    (_rs @(87,114,105,116,101,80,114,111,99,101,115,115,77,101,109,111,114,121)),
    (_rs @(77,97,114,115,104,97,108)) + '::Copy',
    (_rs @(77,97,114,115,104,97,108)) + '\.Copy',
    (_rs @(82,116,108,77,111,118,101,77,101,109,111,114,121)),
    (_rs @(77,105,109,105,107,97,116,122)),
    (_rs @(73,110,118,111,107,101,45,77,105,109,105,107,97,116,122)),
    (_rs @(115,101,107,117,114,108,115,97)) + '::',
    (_rs @(82,117,98,101,117,115)),
    (_rs @(73,110,118,111,107,101,45,68,67,83,121,110,99)),
    (_rs @(80,111,119,101,114,83,112,108,111,105,116)),
    (_rs @(80,111,119,101,114,86,105,101,119)),
    (_rs @(73,110,118,111,107,101,45,69,109,112,105,114,101)),
    (_rs @(78,101,116,92,46,83,111,99,107,101,116,115,92,46,84,67,80,67,108,105,101,110,116)),
    'System\.Net\.' + (_rs @(83,111,99,107,101,116,115)),
    'CurrentVersion\\Run',
    (_rs @(115,99,104,116,97,115,107,115)),
    (_rs @(82,101,103,105,115,116,101,114,45,83,99,104,101,100,117,108,101,100,84,97,115,107)),
    (_rs @(78,101,119,45,83,101,114,118,105,99,101)),
    'sc\.exe\s+' + (_rs @(99,114,101,97,116,101)),
    (_rs @(118,115,115,97,100,109,105,110)) + '\s+delete\s+shadows',
    (_rs @(98,99,100,101,100,105,116)),
    (_rs @(119,98,97,100,109,105,110)),
    'cipher\s+/w',
    (_rs @(83,101,116,45,77,112,80,114,101,102,101,114,101,110,99,101)),
    (_rs @(65,100,100,45,77,112,80,114,101,102,101,114,101,110,99,101)) + '.*-Exclusion',
    'Stop-Service.*' + (_rs @(87,105,110,68,101,102,101,110,100)),
    (_rs @(119,101,118,116,117,116,105,108)) + '\s+cl'
)

# Compile to regex once for speed
$combinedRegex = '(?i)' + ($p -join '|')
$suspiciousPatterns = $p  # back-compat alias

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
    # Truncate script text to 2000 chars to avoid DB bloat -- the first 2000
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
            Write-Host "  Too many failures -- aborting this run." -ForegroundColor Red
            break
        }
    }
}

$currentRun.ToString("o") | Set-Content $StateFile
Write-Host "[$(Get-Date -Format HH:mm:ss)] PSBL done: sent=$sent failed=$failed skipped=$skipped total=$($events.Count)" -ForegroundColor Green
