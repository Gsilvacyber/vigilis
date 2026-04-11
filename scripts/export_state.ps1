# export_state.ps1
# Captures periodic snapshots of host configuration (services, scheduled
# tasks, autoruns, local users, installed programs, listening ports) and
# diffs against the previous snapshot. Only DRIFT (new/removed/modified
# items) is POSTed to Vigilis. The first run is a baseline (no POSTs).
#
# This exporter complements the event-stream exporters by giving Vigilis
# a view of the host's STANDING CONFIGURATION — the "what exists"
# complement to "what happened".
#
# Schedule hourly via Task Scheduler.

param(
    [string]$VigilisUrl = "http://192.168.184.1:8000",
    [string]$ApiKey = "socai-demo-key-do-not-use-in-production",
    [string]$StateDir = "C:\ProgramData\Vigilis\state",
    [int]$MaxEventsPerRun = 50,
    [switch]$ShowDetails
)

$ErrorActionPreference = "Continue"

# Ensure state directory exists with restrictive ACL
if (-not (Test-Path $StateDir)) {
    New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
    # Restrict ACL: SYSTEM + Administrators only
    try {
        $acl = Get-Acl $StateDir
        $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
        $rules = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM", "FullControl",
                "ContainerInherit,ObjectInherit", "None", "Allow"),
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators", "FullControl",
                "ContainerInherit,ObjectInherit", "None", "Allow")
        )
        foreach ($r in $rules) { $acl.AddAccessRule($r) }
        Set-Acl -Path $StateDir -AclObject $acl
    } catch {
        Write-Host "  Warning: could not set restrictive ACL on $StateDir" -ForegroundColor Yellow
    }
}

$hostname = $env:COMPUTERNAME.ToLower()
$upn = "$($env:USERNAME.ToLower())@$($env:USERDOMAIN.ToLower()).local"
$currentRun = Get-Date

# ---- Snapshot functions ----

function Get-ServiceSnapshot {
    try {
        Get-CimInstance Win32_Service -ErrorAction Stop |
            Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
            ForEach-Object {
                @{
                    id       = $_.Name.ToLower()
                    item     = $_.Name
                    pathName = $_.PathName
                    state    = $_.State
                    startMode = $_.StartMode
                    startName = $_.StartName
                }
            }
    } catch {
        @()
    }
}

function Get-ScheduledTaskSnapshot {
    try {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $task = $_
            $actions = @()
            try {
                foreach ($a in $task.Actions) {
                    if ($a.Execute) {
                        $actions += "$($a.Execute) $($a.Arguments)"
                    }
                }
            } catch {}
            @{
                id      = ($task.TaskPath + $task.TaskName).ToLower()
                item    = "$($task.TaskPath)$($task.TaskName)"
                actions = ($actions -join "; ")
                state   = $task.State.ToString()
                author  = $task.Author
            }
        }
    } catch {
        @()
    }
}

function Get-LocalUserSnapshot {
    try {
        Get-LocalUser -ErrorAction Stop | ForEach-Object {
            @{
                id            = $_.Name.ToLower()
                item          = $_.Name
                sid           = $_.SID.Value
                enabled       = $_.Enabled
                lastLogon     = if ($_.LastLogon) { $_.LastLogon.ToString("o") } else { $null }
                passwordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("o") } else { $null }
                description   = $_.Description
            }
        }
    } catch {
        @()
    }
}

function Get-AutorunSnapshot {
    $entries = @()
    # Registry Run/RunOnce keys (15 most abused per Phase 3 plan)
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        try {
            if (Test-Path $key) {
                $props = Get-ItemProperty -Path $key -ErrorAction Stop
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                        $entries += @{
                            id      = "$key\$($prop.Name)".ToLower()
                            item    = "$key\$($prop.Name)"
                            target  = "$($prop.Value)"
                            keyType = "RunKey"
                        }
                    }
                }
            }
        } catch {}
    }
    # Winlogon Shell/Userinit hijacks
    try {
        $winlogon = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        foreach ($name in @('Shell', 'Userinit', 'Notify')) {
            $val = $winlogon.$name
            if ($val) {
                $entries += @{
                    id      = "winlogon.$name".ToLower()
                    item    = "HKLM\...\Winlogon\$name"
                    target  = "$val"
                    keyType = "Winlogon"
                }
            }
        }
    } catch {}
    # Startup folders
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($sp in $startupPaths) {
        if (Test-Path $sp) {
            try {
                Get-ChildItem -Path $sp -File -ErrorAction Stop | ForEach-Object {
                    $entries += @{
                        id      = $_.FullName.ToLower()
                        item    = $_.FullName
                        target  = $_.FullName
                        keyType = "StartupFolder"
                    }
                }
            } catch {}
        }
    }
    return $entries
}

function Get-InstalledProgramSnapshot {
    $entries = @()
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $uninstallPaths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction Stop |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    $entries += @{
                        id         = "$($_.DisplayName)|$($_.DisplayVersion)".ToLower()
                        item       = $_.DisplayName
                        version    = $_.DisplayVersion
                        publisher  = $_.Publisher
                        installDate = $_.InstallDate
                    }
                }
        } catch {}
    }
    return $entries
}

# ---- Diff and POST ----

$categories = @{
    "service"           = @{ getter = { Get-ServiceSnapshot } }
    "scheduled_task"    = @{ getter = { Get-ScheduledTaskSnapshot } }
    "local_user"        = @{ getter = { Get-LocalUserSnapshot } }
    "autorun"           = @{ getter = { Get-AutorunSnapshot } }
    "installed_program" = @{ getter = { Get-InstalledProgramSnapshot } }
}

$totalSent = 0
$totalFailed = 0
$totalDrifts = 0

foreach ($categoryName in $categories.Keys) {
    $snapshotFile = Join-Path $StateDir "$categoryName.json"
    $current = & $categories[$categoryName].getter
    if (-not $current) { $current = @() }

    # Index current snapshot by id for diff
    $currentIndex = @{}
    foreach ($c in $current) {
        if ($c.id) { $currentIndex[$c.id] = $c }
    }

    # Load previous snapshot (if any)
    $previous = $null
    if (Test-Path $snapshotFile) {
        try {
            $rawPrev = Get-Content $snapshotFile -Raw -ErrorAction Stop
            $previous = ConvertFrom-Json $rawPrev -ErrorAction Stop
        } catch {
            $previous = $null
        }
    }

    # First run = baseline only, no POSTs
    if (-not $previous) {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] Baseline snapshot for $categoryName ($($current.Count) items, no POSTs)" -ForegroundColor Gray
        # Save current as the new baseline
        $current | ConvertTo-Json -Depth 5 | Set-Content -Path $snapshotFile -Encoding UTF8
        continue
    }

    # Index previous for diff
    $prevIndex = @{}
    foreach ($p in $previous) {
        if ($p.id) { $prevIndex[$p.id] = $p }
    }

    # Find additions (in current, not in previous)
    $drifts = @()
    foreach ($id in $currentIndex.Keys) {
        if (-not $prevIndex.ContainsKey($id)) {
            $drifts += @{
                action = "added"
                item   = $currentIndex[$id]
            }
        }
    }
    # Find removals (in previous, not in current)
    foreach ($id in $prevIndex.Keys) {
        if (-not $currentIndex.ContainsKey($id)) {
            $drifts += @{
                action = "removed"
                item   = $prevIndex[$id]
            }
        }
    }

    if ($drifts.Count -eq 0) {
        if ($ShowDetails) {
            Write-Host "  [$categoryName] no drift ($($current.Count) items)" -ForegroundColor Gray
        }
        $current | ConvertTo-Json -Depth 5 | Set-Content -Path $snapshotFile -Encoding UTF8
        continue
    }

    $totalDrifts += $drifts.Count
    Write-Host "[$(Get-Date -Format HH:mm:ss)] [$categoryName] $($drifts.Count) drift events detected" -ForegroundColor Cyan

    # Cap drifts to MaxEventsPerRun per category
    $driftsToSend = $drifts | Select-Object -First $MaxEventsPerRun

    foreach ($drift in $driftsToSend) {
        $item = $drift.item
        $action = $drift.action

        # Convert item's additional props into a _driftDetails dict for the backend
        $details = @{}
        foreach ($key in $item.Keys) {
            if ($key -notin @("id", "item")) {
                $details[$key] = $item[$key]
            }
        }

        $rawAlert = @{
            identity       = @{ upn = $upn }
            device         = @{ hostname = $hostname; managed = $true }
            _stateCategory = $categoryName
            _driftAction   = $action
            _driftItem     = $item.item
            _driftDetails  = $details
        }

        # For service drift, also set _servicePath so check_state_drift fires
        if ($categoryName -eq "service" -and $item.pathName) {
            $rawAlert._servicePath = $item.pathName
        }

        $title = "$action $categoryName`: $($item.item)"
        $description = "State drift: $action $categoryName '$($item.item)' on $hostname"

        $payload = @{
            tenantId      = "sysmon-live"
            customer      = @{ name = "Home Lab"; environment = "prod" }
            source        = @{
                sourceSystem   = "edr"
                sourceName     = "StateSnapshot"
                sourceAlertId  = "drift-$categoryName-$([guid]::NewGuid().ToString('N').Substring(0,12))"
                sourceSeverity = "low"
            }
            alertType     = "endpoint.stateDrift"
            title         = $title
            description   = $description
            severity      = "low"
            eventTime     = $currentRun.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            rawAlert      = $rawAlert
        } | ConvertTo-Json -Depth 10 -Compress

        try {
            $null = Invoke-RestMethod -Uri "$VigilisUrl/api/v1/cases" `
                -Method POST `
                -Headers @{ "X-API-Key" = $ApiKey; "Content-Type" = "application/json" } `
                -Body $payload `
                -TimeoutSec 15 `
                -ErrorAction Stop
            $totalSent++
            if ($ShowDetails) {
                Write-Host "  [OK] $action $categoryName : $($item.item)" -ForegroundColor Green
            }
        } catch {
            $totalFailed++
            Write-Host "  [FAIL] $action $categoryName : $($_.Exception.Message)" -ForegroundColor Yellow
            if ($totalFailed -ge 5) {
                Write-Host "  Too many failures — aborting this run." -ForegroundColor Red
                break
            }
        }
    }

    # Save new snapshot
    $current | ConvertTo-Json -Depth 5 | Set-Content -Path $snapshotFile -Encoding UTF8
}

Write-Host "[$(Get-Date -Format HH:mm:ss)] State drift done: drifts=$totalDrifts sent=$totalSent failed=$totalFailed" -ForegroundColor Green
