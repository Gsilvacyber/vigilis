# export_sysmon.ps1
# Reads Sysmon events from Windows Event Log and POSTs them to Vigilis as alerts.
# Builds a real behavioral baseline in the entity graph from actual endpoint activity.
#
# Usage:
#   .\export_sysmon.ps1 -VigilisUrl "http://192.168.184.1:8000"
#
# Schedule every 5 minutes via Task Scheduler.

param(
    [string]$VigilisUrl = "http://192.168.184.1:8000",
    [string]$ApiKey = "socai-demo-key-do-not-use-in-production",
    [int]$LookbackMinutes = 5,
    [int]$MaxEventsPerRun = 25,
    [string]$StateFile = "$env:TEMP\sysmon_export_state.txt",
    [switch]$ShowDetails
)

$ErrorActionPreference = "Continue"

# ---- State management: track last run time to avoid duplicates ----
if (Test-Path $StateFile) {
    try {
        $lastRunStr = Get-Content $StateFile -ErrorAction Stop
        $lastRun = [datetime]::Parse($lastRunStr)
    } catch {
        $lastRun = (Get-Date).AddMinutes(-$LookbackMinutes)
    }
} else {
    $lastRun = (Get-Date).AddMinutes(-$LookbackMinutes)
}
$currentRun = Get-Date

# ---- EventID to Vigilis alert type mapping ----
$eventMap = @{
    1  = @{ type = "endpoint.suspiciousProcess";     severity = "medium" }
    3  = @{ type = "network.commandAndControl";      severity = "medium" }
    11 = @{ type = "endpoint.malwareDetection";      severity = "low"    }
    12 = @{ type = "endpoint.persistenceMechanism";  severity = "medium" }
    13 = @{ type = "endpoint.persistenceMechanism";  severity = "medium" }
    22 = @{ type = "network.dnsAnomaly";             severity = "low"    }
}

# ---- Noise filtering: skip common benign processes ----
$benignProcessPatterns = @(
    '\\svchost\.exe$',
    '\\services\.exe$',
    '\\lsass\.exe$',
    '\\csrss\.exe$',
    '\\smss\.exe$',
    '\\wininit\.exe$',
    '\\winlogon\.exe$',
    '\\dwm\.exe$',
    '\\fontdrvhost\.exe$',
    '\\sihost\.exe$',
    '\\ctfmon\.exe$',
    '\\RuntimeBroker\.exe$',
    '\\SearchHost\.exe$',
    '\\SearchIndexer\.exe$',
    '\\SgrmBroker\.exe$',
    '\\conhost\.exe$',
    '\\taskhostw\.exe$',
    '\\audiodg\.exe$',
    '\\spoolsv\.exe$',
    '\\MsMpEng\.exe$',
    '\\SecurityHealthSystray\.exe$',
    '\\SecurityHealthService\.exe$',
    '\\SystemSettings\.exe$',
    '\\explorer\.exe$',
    '\\ShellExperienceHost\.exe$',
    '\\StartMenuExperienceHost\.exe$'
)

# Skip private/loopback IPs for network events
$privateIpPatterns = @(
    '^127\.',
    '^10\.',
    '^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    '^192\.168\.',
    '^169\.254\.',
    '^::1$',
    '^fe80:',
    '^fc00:',
    '^fd',
    '^224\.',
    '^239\.',
    '^255\.255\.255\.255$',
    '^0\.0\.0\.0$'
)

# Skip common benign DNS queries
$benignDomainPatterns = @(
    'windowsupdate\.com$',
    'microsoft\.com$',
    'msftncsi\.com$',
    'msftconnecttest\.com$',
    'windows\.com$',
    'office\.com$',
    'live\.com$',
    'wns\.windows\.com$',
    'bing\.com$',
    'google\.com$',
    'gstatic\.com$',
    '\.in-addr\.arpa$',
    '\.ip6\.arpa$',
    '^localhost$',
    '^wpad$'
)

# ---- Query Sysmon events ----
$filter = @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    StartTime = $lastRun
    Id        = @(1, 3, 11, 12, 13, 22)
}

$events = @()
try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop
} catch {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] No new Sysmon events since $lastRun" -ForegroundColor Gray
    } else {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] Error reading Sysmon log: $($_.Exception.Message)" -ForegroundColor Red
    }
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

if ($events.Count -eq 0) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] No new Sysmon events since $lastRun" -ForegroundColor Gray
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

Write-Host "[$(Get-Date -Format HH:mm:ss)] Found $($events.Count) Sysmon events since $lastRun" -ForegroundColor Cyan

# ---- Filter and transform events ----
$hostname = $env:COMPUTERNAME.ToLower()
$upn = "$($env:USERNAME.ToLower())@$($env:USERDOMAIN.ToLower()).local"
$sent = 0
$failed = 0
$skipped = 0
$filteredEvents = @()

foreach ($event in $events) {
    $mapping = $eventMap[[int]$event.Id]
    if (-not $mapping) { continue }

    $xml = [xml]$event.ToXml()
    $eventData = @{}
    foreach ($data in $xml.Event.EventData.Data) {
        $eventData[$data.Name] = $data.'#text'
    }

    $eventId = [int]$event.Id
    $skip = $false

    if ($eventId -eq 1) {
        $image = $eventData.Image
        if ($image) {
            foreach ($pattern in $benignProcessPatterns) {
                if ($image -match $pattern) { $skip = $true; break }
            }
        }
    } elseif ($eventId -eq 3) {
        $dstIp = $eventData.DestinationIp
        if (-not $dstIp) { $skip = $true }
        else {
            foreach ($pattern in $privateIpPatterns) {
                if ($dstIp -match $pattern) { $skip = $true; break }
            }
        }
    } elseif ($eventId -eq 22) {
        $qname = $eventData.QueryName
        if (-not $qname) { $skip = $true }
        else {
            foreach ($pattern in $benignDomainPatterns) {
                if ($qname -match $pattern) { $skip = $true; break }
            }
        }
    }

    if ($skip) {
        $skipped++
        continue
    }

    $filteredEvents += @{ Event = $event; Data = $eventData; Mapping = $mapping }
}

if ($filteredEvents.Count -eq 0) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] All $($events.Count) events filtered as noise" -ForegroundColor Gray
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

$toSend = $filteredEvents | Select-Object -First $MaxEventsPerRun
Write-Host "[$(Get-Date -Format HH:mm:ss)] Sending $($toSend.Count) events (filtered $skipped, capped at $MaxEventsPerRun)" -ForegroundColor Cyan

# ---- POST each event to Vigilis ----
foreach ($item in $toSend) {
    $event = $item.Event
    $eventData = $item.Data
    $mapping = $item.Mapping
    $eventId = [int]$event.Id

    $eventUser = $eventData.User
    $identityUpn = if ($eventUser) { $eventUser.ToLower() } else { $upn }

    $rawAlert = @{
        identity = @{ upn = $identityUpn }
        device   = @{ hostname = $hostname; managed = $true }
    }

    $title = "Sysmon event $eventId"
    $description = "Sysmon event $eventId on $hostname"

    switch ($eventId) {
        1 {
            $imagePath = $eventData.Image
            $procName = if ($imagePath) { Split-Path $imagePath -Leaf } else { "unknown.exe" }
            $rawAlert.process = $imagePath
            $rawAlert._processName = $procName
            $rawAlert.commandLine = $eventData.CommandLine
            $rawAlert._parentProcess = $eventData.ParentImage
            $sha256 = ""
            if ($eventData.Hashes -and $eventData.Hashes -match 'SHA256=([A-F0-9]+)') {
                $sha256 = $matches[1].ToLower()
            }
            $rawAlert.file = @{
                fileName = $procName
                filePath = $imagePath
                sha256   = $sha256
                signer   = if ($eventData.SignerName) { $eventData.SignerName } else { "" }
            }
            $title = "New process: $procName"
            $description = "Sysmon detected process execution: $imagePath (parent: $($eventData.ParentImage))"
        }
        3 {
            $dstIp = $eventData.DestinationIp
            $srcIp = $eventData.SourceIp
            $rawAlert.process = $eventData.Image
            $rawAlert.dst_ip = $dstIp
            $rawAlert.src_ip = $srcIp
            $rawAlert.ips = @(
                @{ ipAddress = $dstIp; role = "destination" }
                @{ ipAddress = $srcIp; role = "source" }
            )
            if ($eventData.DestinationHostname) {
                $rawAlert.domain = $eventData.DestinationHostname
            }
            $rawAlert._destinationPort = $eventData.DestinationPort
            $title = "Outbound connection to $dstIp"
            $description = "Process $($eventData.Image) connected to $dstIp on port $($eventData.DestinationPort)"
        }
        11 {
            $targetFile = $eventData.TargetFilename
            $fileName = if ($targetFile) { Split-Path $targetFile -Leaf } else { "unknown" }
            $rawAlert.file = @{
                fileName = $fileName
                filePath = $targetFile
            }
            $rawAlert.process = $eventData.Image
            $title = "File created: $fileName"
            $description = "Process $($eventData.Image) created file $targetFile"
        }
        12 {
            $rawAlert.process = $eventData.Image
            $rawAlert._registryKey = $eventData.TargetObject
            $rawAlert._registryOperation = "CreateKey"
            $title = "Registry key created"
            $description = "Process $($eventData.Image) created registry object $($eventData.TargetObject)"
        }
        13 {
            $rawAlert.process = $eventData.Image
            $rawAlert._registryKey = $eventData.TargetObject
            $rawAlert._registryValue = $eventData.Details
            $rawAlert._registryOperation = "SetValue"
            $title = "Registry value modified"
            $description = "Process $($eventData.Image) modified registry value $($eventData.TargetObject)"
        }
        22 {
            $rawAlert.process = $eventData.Image
            $rawAlert.domain = $eventData.QueryName
            $rawAlert._dnsQueryName = $eventData.QueryName
            $rawAlert._dnsQueryResults = $eventData.QueryResults
            $title = "DNS query: $($eventData.QueryName)"
            $description = "Process $($eventData.Image) queried DNS for $($eventData.QueryName)"
        }
    }

    $payload = @{
        tenantId      = "sysmon-live"
        customer      = @{ name = "Home Lab"; environment = "prod" }
        source        = @{
            sourceSystem   = "edr"
            sourceName     = "Sysmon"
            sourceAlertId  = "sysmon-$($event.RecordId)"
            sourceSeverity = $mapping.severity
        }
        alertType     = $mapping.type
        title         = $title
        description   = $description
        severity      = $mapping.severity
        eventTime     = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
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
            Write-Host "  [OK] EventID $eventId : $title" -ForegroundColor Green
        }
    } catch {
        $failed++
        $errorDetail = ""
        try {
            if ($_.Exception.Response) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errorDetail = $reader.ReadToEnd()
                $reader.Close()
            }
        } catch {}
        Write-Host "  [FAIL] EventID $eventId : $($_.Exception.Message)" -ForegroundColor Yellow
        if ($errorDetail) {
            Write-Host "  Response body: $errorDetail" -ForegroundColor DarkYellow
        }
        if ($failed -eq 1) {
            Write-Host "  DEBUG payload: $payload" -ForegroundColor DarkCyan
        }
        if ($failed -ge 5) {
            Write-Host "  Too many failures - aborting this run. Check Vigilis URL: $VigilisUrl" -ForegroundColor Red
            break
        }
    }
}

$currentRun.ToString("o") | Set-Content $StateFile

Write-Host "[$(Get-Date -Format HH:mm:ss)] Done: sent=$sent failed=$failed skipped=$skipped total=$($events.Count)" -ForegroundColor Green
