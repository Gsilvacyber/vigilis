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
    # Phase 2.3: EID 10 process access (filter to LSASS only in Sysmon config)
    10 = @{ type = "endpoint.lsassAccess";           severity = "high"   }
    11 = @{ type = "endpoint.malwareDetection";      severity = "low"    }
    12 = @{ type = "endpoint.persistenceMechanism";  severity = "medium" }
    13 = @{ type = "endpoint.persistenceMechanism";  severity = "medium" }
    # Phase 2.3: EIDs 17/18 pipe create/connect (lateral movement C2)
    17 = @{ type = "endpoint.pipeActivity";          severity = "medium" }
    18 = @{ type = "endpoint.pipeActivity";          severity = "medium" }
    # Phase 2.3: EIDs 19/20/21 WMI persistence
    19 = @{ type = "endpoint.wmiPersistence";        severity = "high"   }
    20 = @{ type = "endpoint.wmiPersistence";        severity = "high"   }
    21 = @{ type = "endpoint.wmiPersistence";        severity = "high"   }
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

# Skip benign file-create events by full directory prefix (EventID 11).
# These paths are dominated by Windows Update, Microsoft Store, Defender
# definitions, and error reporting -- all of which are normal activity.
$benignFileCreatePathPatterns = @(
    '^C:\\Windows\\WinSxS\\',
    '^C:\\Windows\\SoftwareDistribution\\',
    '^C:\\Windows\\Installer\\',
    '^C:\\Windows\\servicing\\LCU\\',
    '^C:\\Windows\\System32\\DriverStore\\',
    '^C:\\Windows\\System32\\config\\',
    '^C:\\Windows\\Logs\\',
    '^C:\\Windows\\Prefetch\\',
    '^C:\\Windows\\Temp\\[^\\]+\.tmp$',
    '^C:\\Program Files\\WindowsApps\\',
    '^C:\\Program Files\\WindowsPowerShell\\Modules\\PackageManagement\\',
    '^C:\\Program Files \(x86\)\\Microsoft\\EdgeUpdate\\',
    '^C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\',
    '^C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\',
    '^C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\',
    '^C:\\ProgramData\\Microsoft\\Windows\\WER\\',
    '^C:\\ProgramData\\Microsoft\\Windows\\AppRepository\\',
    '^C:\\ProgramData\\Microsoft\\Diagnosis\\',
    '^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Edge\\User Data\\',
    '^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\OneDrive\\',
    '^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\INetCache\\',
    '^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\WebCache\\',
    '^C:\\Users\\[^\\]+\\AppData\\Local\\Packages\\',
    '^C:\\Users\\[^\\]+\\AppData\\Local\\ConnectedDevicesPlatform\\',
    '^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Teams\\'
)

# Skip file-create events written by these benign "churn" processes.
# These processes legitimately write thousands of files daily; we only want
# to see OTHER processes writing files (user downloads, shells, malware).
$benignFileCreateWriters = @(
    '\\svchost\.exe$',
    '\\TiWorker\.exe$',
    '\\TrustedInstaller\.exe$',
    '\\MsMpEng\.exe$',
    '\\MpCmdRun\.exe$',
    '\\MoUsoCoreWorker\.exe$',
    '\\SearchIndexer\.exe$',
    '\\OneDrive\.exe$',
    '\\msedge\.exe$',
    '\\CompatTelRunner\.exe$',
    '\\DismHost\.exe$',
    '\\taskhostw\.exe$',
    '\\RuntimeBroker\.exe$',
    '\\smartscreen\.exe$',
    '\\SgrmBroker\.exe$',
    '\\explorer\.exe$',
    '\\ShellExperienceHost\.exe$',
    '\\backgroundTaskHost\.exe$',
    '\\wsqmcons\.exe$',
    '\\SIHClient\.exe$',
    '\\WerFault\.exe$',
    '\\WerFaultSecure\.exe$'
)

# ---- Query Sysmon events ----
$filter = @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    StartTime = $lastRun
    # Phase 2.3 expanded EID set: 10 (LSASS access), 17/18 (pipes),
    # 19/20/21 (WMI persistence) -- requires sysmonconfig.xml to enable them
    Id        = @(1, 3, 10, 11, 12, 13, 17, 18, 19, 20, 21, 22)
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
$skippedFilePath = 0
$skippedFileWriter = 0
$skippedProcDup = 0
$filteredEvents = @()

# Track process-create events seen this run to dedup (image|commandLine|user)
$procCreateSeen = @{}

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
        # Process create: skip benign writers first
        $image = $eventData.Image
        if ($image) {
            foreach ($pattern in $benignProcessPatterns) {
                if ($image -match $pattern) { $skip = $true; break }
            }
        }
        # Dedup: same (image + commandLine + user) within the 5-min window
        if (-not $skip) {
            $dedupKey = "$($eventData.Image)|$($eventData.CommandLine)|$($eventData.User)"
            if ($procCreateSeen.ContainsKey($dedupKey)) {
                $skip = $true
                $skippedProcDup++
            } else {
                $procCreateSeen[$dedupKey] = $true
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
    } elseif ($eventId -eq 11) {
        # File create: filter by target file path and writer process.
        # Before Phase 1 we had zero EID 11 filters -- ~50% of cases were
        # Microsoft Store / Windows Update file writes. Now we drop them.
        $targetFile = $eventData.TargetFilename
        $writerImage = $eventData.Image
        if ($targetFile) {
            foreach ($pattern in $benignFileCreatePathPatterns) {
                if ($targetFile -match $pattern) {
                    $skip = $true
                    $skippedFilePath++
                    break
                }
            }
        }
        if (-not $skip -and $writerImage) {
            foreach ($pattern in $benignFileCreateWriters) {
                if ($writerImage -match $pattern) {
                    $skip = $true
                    $skippedFileWriter++
                    break
                }
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

# ---- File-create aggregation ----
# Group EventID 11 events by (writer_image, target_directory, user). If a
# group has >3 events in the 5-min window, collapse them into ONE synthesized
# mass_file_create alert. Mass-write is the actual ransomware signal -- we
# preserve it without flooding the case list with 20 separate alerts.
$fileCreateGroups = @{}
$nonFileCreate = @()
$skippedFileAggregated = 0

foreach ($item in $filteredEvents) {
    $e = $item.Event
    if ([int]$e.Id -ne 11) {
        $nonFileCreate += $item
        continue
    }
    $d = $item.Data
    $dir = ""
    if ($d.TargetFilename) {
        try { $dir = [System.IO.Path]::GetDirectoryName($d.TargetFilename) } catch { $dir = "" }
    }
    $groupKey = "$($d.Image)|$dir|$($d.User)"
    if (-not $fileCreateGroups.ContainsKey($groupKey)) {
        $fileCreateGroups[$groupKey] = @()
    }
    $fileCreateGroups[$groupKey] += $item
}

$collapsedEvents = @()
foreach ($groupKey in $fileCreateGroups.Keys) {
    $group = $fileCreateGroups[$groupKey]
    if ($group.Count -gt 3) {
        # Collapse into one synthesized mass_file_create event
        $first = $group[0]
        $d = $first.Data
        $dir = ""
        if ($d.TargetFilename) {
            try { $dir = [System.IO.Path]::GetDirectoryName($d.TargetFilename) } catch { $dir = "" }
        }
        $filenames = @()
        $extensions = @{}
        foreach ($g in $group) {
            if ($g.Data.TargetFilename) {
                try {
                    $fn = [System.IO.Path]::GetFileName($g.Data.TargetFilename)
                    if ($filenames.Count -lt 5) { $filenames += $fn }
                    $ext = [System.IO.Path]::GetExtension($fn)
                    if ($ext) { $extensions[$ext] = $true }
                } catch {}
            }
        }
        # Synthesize a new event record with special mapping
        $syntheticMapping = @{ type = "endpoint.massFileCreate"; severity = "medium" }
        $syntheticData = @{
            Image = $d.Image
            TargetFilename = $d.TargetFilename
            User = $d.User
            _fileCreateCount = $group.Count
            _fileCreateDirectory = $dir
            _fileCreateExamples = ($filenames -join ", ")
            _fileCreateExtensions = (($extensions.Keys) -join ", ")
        }
        $collapsedEvents += @{
            Event = $first.Event  # use first event's timestamp/RecordId
            Data = $syntheticData
            Mapping = $syntheticMapping
            IsSynthesized = $true
        }
        $skippedFileAggregated += ($group.Count - 1)
    } else {
        # Keep as individual events
        foreach ($g in $group) { $collapsedEvents += $g }
    }
}

$filteredEvents = $nonFileCreate + $collapsedEvents

if ($filteredEvents.Count -eq 0) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] All $($events.Count) events filtered as noise" -ForegroundColor Gray
    Write-Host "  skipped: path=$skippedFilePath writer=$skippedFileWriter aggregated=$skippedFileAggregated procDup=$skippedProcDup" -ForegroundColor Gray
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

$toSend = $filteredEvents | Select-Object -First $MaxEventsPerRun
Write-Host "[$(Get-Date -Format HH:mm:ss)] Sending $($toSend.Count) events (filtered $skipped, capped at $MaxEventsPerRun)" -ForegroundColor Cyan
Write-Host "  noise-reduction counts: path=$skippedFilePath writer=$skippedFileWriter aggregated=$skippedFileAggregated procDup=$skippedProcDup" -ForegroundColor Gray

# ---- POST each event to Vigilis ----
foreach ($item in $toSend) {
    $event = $item.Event
    $eventData = $item.Data
    $mapping = $item.Mapping
    $eventId = [int]$event.Id
    $isSynthesized = $false
    if ($item.ContainsKey("IsSynthesized")) { $isSynthesized = $item.IsSynthesized }

    $eventUser = $eventData.User
    $identityUpn = if ($eventUser) { $eventUser.ToLower() } else { $upn }

    $rawAlert = @{
        identity = @{ upn = $identityUpn }
        device   = @{ hostname = $hostname; managed = $true }
    }

    $title = "Sysmon event $eventId"
    $description = "Sysmon event $eventId on $hostname"

    # Synthesized mass_file_create event (Phase 1.2 aggregation).
    # Skip the normal EID switch for these -- they carry their own
    # synthesized rawAlert fields and alertType.
    if ($isSynthesized -and $mapping.type -eq "endpoint.massFileCreate") {
        $rawAlert.process = $eventData.Image
        $rawAlert._fileCreateCount = $eventData._fileCreateCount
        $rawAlert._fileCreateDirectory = $eventData._fileCreateDirectory
        $rawAlert._fileCreateExamples = $eventData._fileCreateExamples
        $rawAlert._fileCreateExtensions = $eventData._fileCreateExtensions
        $count = $eventData._fileCreateCount
        $dir = $eventData._fileCreateDirectory
        $title = "Mass file create: $count files in $dir"
        $description = "Process $($eventData.Image) wrote $count files to $dir (examples: $($eventData._fileCreateExamples))"
        # Jump past the switch -- assign a marker EID no case matches
        $eventId = -1
    }

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
        # -- Phase 2.3: new Sysmon EventIDs --
        10 {
            # Process Access -- filtered by sysmonconfig.xml to LSASS-only.
            # Translator's event-ID fork will set _lsassAccess=True + T1003.001.
            $rawAlert.process = $eventData.SourceImage
            $rawAlert._targetImage = $eventData.TargetImage
            $rawAlert._grantedAccess = $eventData.GrantedAccess
            $rawAlert._sysmonEventId = 10
            $title = "Process access: $(Split-Path $eventData.SourceImage -Leaf) -> $(Split-Path $eventData.TargetImage -Leaf)"
            $description = "Source $($eventData.SourceImage) accessed target $($eventData.TargetImage) (rights=$($eventData.GrantedAccess))"
        }
        { $_ -in 17, 18 } {
            # Pipe Create (17) or Pipe Connected (18)
            $rawAlert.process = $eventData.Image
            $rawAlert._pipeName = $eventData.PipeName
            $rawAlert._sysmonEventId = $eventId
            $action = if ($eventId -eq 17) { "created" } else { "connected to" }
            $title = "Named pipe $action`: $($eventData.PipeName)"
            $description = "Process $($eventData.Image) $action named pipe $($eventData.PipeName)"
        }
        { $_ -in 19, 20, 21 } {
            # WMI Event Filter (19), Consumer (20), FilterToConsumerBinding (21)
            $rawAlert.process = $eventData.User
            $rawAlert._wmiOperation = $eventData.Operation
            $rawAlert._wmiNamespace = $eventData.EventNamespace
            $rawAlert._wmiFilter = $eventData.Filter
            $rawAlert._wmiConsumer = $eventData.Consumer
            $rawAlert._wmiName = $eventData.Name
            $rawAlert._sysmonEventId = $eventId
            $kind = @{19="Filter";20="Consumer";21="Binding"}[$eventId]
            $title = "WMI ${kind}: $($eventData.Name)"
            $description = "WMI persistence event ID $eventId ($kind) detected"
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

# ---- Heartbeat POST (Days 1-3 observability) ----
# Always POSTs at end-of-run, even when zero events were sent. This is what
# lets the backend detect silent data loss — the absence of a heartbeat for
# 10+ minutes means the scheduled task died or the VM is offline.
$heartbeatBody = @{
    exporter        = "sysmon"
    hostname        = $env:COMPUTERNAME.ToLower()
    events_sent     = $sent
    events_filtered = $skipped
    last_run        = (Get-Date).ToUniversalTime().ToString("o")
} | ConvertTo-Json -Compress

try {
    $null = Invoke-RestMethod -Uri "$VigilisUrl/api/v1/exporter/heartbeat" `
        -Method POST `
        -Headers @{ "X-API-Key" = $ApiKey; "Content-Type" = "application/json" } `
        -Body $heartbeatBody `
        -TimeoutSec 10 `
        -ErrorAction Stop
} catch {
    Write-Host "  [HB] Heartbeat POST failed: $($_.Exception.Message)" -ForegroundColor Yellow
}
