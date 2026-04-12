# export_secevt.ps1
# Reads Windows Security Event Log events and POSTs them to Vigilis.
#
# Captures authentication, privilege escalation, account management, and
# audit log clearing events. Complements Sysmon by providing Windows-native
# auth/identity events that Sysmon doesn't see.
#
# EventID coverage:
#   4624 -- Successful logon           -> identity.logonSuccess (new, informational)
#   4625 -- Failed logon               -> identity.suspiciousSignIn (low)
#   4672 -- Special privileges assigned -> identity.privilegeElevation (medium)
#   4688 -- Process creation (native)   -> endpoint.suspiciousProcess (low)
#   4697 -- Service installed           -> endpoint.persistenceMechanism (medium)
#   4698 -- Scheduled task created      -> endpoint.persistenceMechanism (medium)
#   4720 -- User account created        -> identity.accountCreation (new, high)
#   4728 -- Added to global group       -> identity.privilegeElevation (high)
#   4732 -- Added to local group        -> identity.privilegeElevation (high)
#   1102 -- Audit log cleared           -> endpoint.defenseEvasion (critical)
#
# Schedule every 5 minutes via Task Scheduler.

param(
    [string]$VigilisUrl = "http://192.168.184.1:8000",
    [string]$ApiKey = "socai-demo-key-do-not-use-in-production",
    [int]$LookbackMinutes = 5,
    [int]$MaxEventsPerRun = 25,
    [string]$StateFile = "$env:TEMP\secevt_export_state.txt",
    [switch]$ShowDetails
)

$ErrorActionPreference = "Continue"

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

# ---- EventID to Vigilis alert type mapping ----
$eventMap = @{
    4624 = @{ type = "identity.logonSuccess";        severity = "informational" }
    4625 = @{ type = "identity.suspiciousSignIn";    severity = "low"           }
    4672 = @{ type = "identity.privilegeElevation";  severity = "medium"        }
    4688 = @{ type = "endpoint.suspiciousProcess";   severity = "low"           }
    4697 = @{ type = "endpoint.persistenceMechanism"; severity = "medium"       }
    4698 = @{ type = "endpoint.persistenceMechanism"; severity = "medium"       }
    4720 = @{ type = "identity.accountCreation";     severity = "high"          }
    4728 = @{ type = "identity.privilegeElevation";  severity = "high"          }
    4732 = @{ type = "identity.privilegeElevation";  severity = "high"          }
    1102 = @{ type = "endpoint.defenseEvasion";      severity = "critical"      }
}

# 4624 logon type filter: only interesting logons.
# 2  = Interactive, 3  = Network, 7  = Unlock,
# 10 = RemoteInteractive (RDP), 11 = CachedInteractive
$interestingLogonTypes = @(2, 3, 7, 10, 11)

# Skip service accounts that flood 4624 (these aren't interesting for
# behavioral baselines -- they're constant background).
$benignServiceAccounts = @(
    '^(NT AUTHORITY|ANONYMOUS LOGON|LOCAL SERVICE|NETWORK SERVICE)',
    '^SYSTEM$',
    '^DWM-',
    '^UMFD-',
    '^IUSR$'
)

# ---- Query Windows Security Event Log ----
# We query Security and System logs. 1102 lives in the Security log's
# "Audit log cleared" channel, everything else in Security.
$filter = @{
    LogName   = "Security"
    StartTime = $lastRun
    Id        = @(4624, 4625, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 1102)
}

$events = @()
try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop
} catch {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] No new Security Log events since $lastRun" -ForegroundColor Gray
    } else {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] Error reading Security Log: $($_.Exception.Message)" -ForegroundColor Red
    }
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

if ($events.Count -eq 0) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] No new Security Log events since $lastRun" -ForegroundColor Gray
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

Write-Host "[$(Get-Date -Format HH:mm:ss)] Found $($events.Count) Security Log events since $lastRun" -ForegroundColor Cyan

# ---- Filter and dedup 4624 ----
$hostname = $env:COMPUTERNAME.ToLower()
$sent = 0
$failed = 0
$skipped = 0
$filteredEvents = @()
$seen4624 = @{}  # dedup key: user|ip|logonType

foreach ($event in $events) {
    $eid = [int]$event.Id
    $mapping = $eventMap[$eid]
    if (-not $mapping) { continue }

    $xml = [xml]$event.ToXml()
    $eventData = @{}
    foreach ($data in $xml.Event.EventData.Data) {
        $eventData[$data.Name] = $data.'#text'
    }

    $skip = $false

    # 4624 specific filters
    if ($eid -eq 4624) {
        $logonType = 0
        try { $logonType = [int]$eventData.LogonType } catch {}
        if ($logonType -notin $interestingLogonTypes) {
            $skip = $true
        }
        # Skip benign service accounts
        $targetUser = $eventData.TargetUserName
        if (-not $skip -and $targetUser) {
            foreach ($p in $benignServiceAccounts) {
                if ($targetUser -match $p) { $skip = $true; break }
            }
        }
        # Dedup: same (user, ip, logontype) within window = just first one
        if (-not $skip) {
            $dedupKey = "$($eventData.TargetUserName)|$($eventData.IpAddress)|$logonType"
            if ($seen4624.ContainsKey($dedupKey)) {
                $skip = $true
            } else {
                $seen4624[$dedupKey] = $true
            }
        }
    }

    if ($skip) {
        $skipped++
        continue
    }

    $filteredEvents += @{ Event = $event; Data = $eventData; Mapping = $mapping; Eid = $eid }
}

if ($filteredEvents.Count -eq 0) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] All $($events.Count) Security Log events filtered as noise" -ForegroundColor Gray
    $currentRun.ToString("o") | Set-Content $StateFile
    exit 0
}

$toSend = $filteredEvents | Select-Object -First $MaxEventsPerRun
Write-Host "[$(Get-Date -Format HH:mm:ss)] Sending $($toSend.Count) Security Log events (filtered $skipped, capped at $MaxEventsPerRun)" -ForegroundColor Cyan

# ---- POST each event ----
foreach ($item in $toSend) {
    $event = $item.Event
    $eventData = $item.Data
    $mapping = $item.Mapping
    $eid = $item.Eid

    # Build identity
    $targetUser = $eventData.TargetUserName
    $targetDomain = $eventData.TargetDomainName
    if ($targetUser -and $targetDomain) {
        $identityUpn = "$($targetUser.ToLower())@$($targetDomain.ToLower())"
    } elseif ($targetUser) {
        $identityUpn = $targetUser.ToLower()
    } else {
        $identityUpn = "$($env:USERNAME.ToLower())@$($env:USERDOMAIN.ToLower()).local"
    }

    $rawAlert = @{
        identity    = @{ upn = $identityUpn }
        device      = @{ hostname = $hostname; managed = $true }
        _sourceEventId = $eid
        _winEventId    = $eid
    }

    # Extract IP addresses from event
    $ipAddr = $eventData.IpAddress
    if ($ipAddr -and $ipAddr -ne "-" -and $ipAddr -ne "::1" -and $ipAddr -ne "127.0.0.1") {
        $rawAlert.ips = @(@{ ipAddress = $ipAddr; role = "source" })
    }

    $title = "Security Event $eid"
    $description = "Windows Security Event $eid on $hostname"

    switch ($eid) {
        4624 {
            $logonType = $eventData.LogonType
            $rawAlert._logonType = $logonType
            $title = "Successful logon: $targetUser (type $logonType)"
            $description = "User $identityUpn logged on (LogonType=$logonType) from $ipAddr"
        }
        4625 {
            $rawAlert._failureReason = $eventData.FailureReason
            $rawAlert._subStatus = $eventData.SubStatus
            # 4625 sub-status 0xC000006A = wrong password (brute force)
            # 0xC0000064 = bad username (enumeration)
            if ($eventData.SubStatus -eq "0xc0000064") {
                $rawAlert._accountEnumeration = $true
            }
            $title = "Failed logon: $targetUser"
            $description = "Failed logon attempt for $identityUpn from $ipAddr (reason: $($eventData.FailureReason))"
        }
        4672 {
            $rawAlert._privilegeEscalation = $true
            $rawAlert._privileges = $eventData.PrivilegeList
            $title = "Special privileges assigned: $targetUser"
            $description = "Privileged logon session for $identityUpn (privileges: $($eventData.PrivilegeList))"
        }
        4688 {
            $rawAlert.process = $eventData.NewProcessName
            $rawAlert.commandLine = $eventData.CommandLine
            $rawAlert._parentProcess = $eventData.ParentProcessName
            $pname = if ($eventData.NewProcessName) { Split-Path $eventData.NewProcessName -Leaf } else { "unknown" }
            $rawAlert._processName = $pname
            $rawAlert.file = @{
                fileName = $pname
                filePath = $eventData.NewProcessName
            }
            $title = "New process (Windows): $pname"
            $description = "Native Windows process creation: $($eventData.NewProcessName) (parent: $($eventData.ParentProcessName))"
        }
        4697 {
            $rawAlert._serviceCreated = $true
            $rawAlert._serviceName = $eventData.ServiceName
            $rawAlert._serviceFile = $eventData.ServiceFileName
            $title = "Service installed: $($eventData.ServiceName)"
            $description = "New Windows service installed: $($eventData.ServiceName) -> $($eventData.ServiceFileName)"
        }
        4698 {
            $rawAlert._scheduledTaskCreated = $true
            $rawAlert._taskName = $eventData.TaskName
            $title = "Scheduled task created: $($eventData.TaskName)"
            $description = "New scheduled task created: $($eventData.TaskName)"
        }
        4720 {
            $rawAlert._accountCreated = $true
            $rawAlert._newAccountName = $eventData.TargetUserName
            $title = "New user account: $($eventData.TargetUserName)"
            $description = "Local user account created: $($eventData.TargetUserName)"
        }
        { $_ -in 4728, 4732 } {
            $rawAlert._privilegeEscalation = $true
            $rawAlert._targetGroup = $eventData.TargetUserName  # group name is in TargetUserName field for 4728/4732
            $rawAlert._memberAdded = $eventData.MemberName
            $title = "Added to group: $($eventData.TargetUserName)"
            $description = "Member added to security-enabled group: $($eventData.MemberName) -> $($eventData.TargetUserName)"
        }
        1102 {
            $rawAlert._logCleared = $true
            $title = "AUDIT LOG CLEARED"
            $description = "Windows Security Audit log was cleared -- potential defense evasion"
        }
    }

    $payload = @{
        tenantId      = "sysmon-live"
        customer      = @{ name = "Home Lab"; environment = "prod" }
        source        = @{
            sourceSystem   = "idp"
            sourceName     = "WindowsEventLog"
            sourceAlertId  = "secevt-$($event.RecordId)"
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
            Write-Host "  [OK] EID $eid : $title" -ForegroundColor Green
        }
    } catch {
        $failed++
        Write-Host "  [FAIL] EID $eid : $($_.Exception.Message)" -ForegroundColor Yellow
        if ($failed -ge 5) {
            Write-Host "  Too many failures -- aborting this run." -ForegroundColor Red
            break
        }
    }
}

$currentRun.ToString("o") | Set-Content $StateFile
Write-Host "[$(Get-Date -Format HH:mm:ss)] Security Log done: sent=$sent failed=$failed skipped=$skipped total=$($events.Count)" -ForegroundColor Green

# ---- Heartbeat POST (Days 1-3 observability) ----
$heartbeatBody = @{
    exporter        = "secevt"
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
