# ============================================================================
# Atomic Red Team Setup + Vigilis Attack Simulation Runner
# ============================================================================
#
# WHAT THIS DOES:
#   1. Installs Atomic Red Team (open-source attack simulation framework)
#   2. Runs 10 safe MITRE ATT&CK tests that generate REAL Sysmon + PSBL telemetry
#   3. Your existing Vigilis exporters (sysmon/psbl/secevt) automatically capture
#      the events and POST them to the Vigilis API
#   4. The enrichment pipeline scores them as real attacks -- no fake JSON fixtures
#
# REQUIREMENTS:
#   - Run as Administrator on the Windows 11 VM
#   - Sysmon must be installed and running
#   - Vigilis exporters must be running (export_sysmon.ps1, export_psbl.ps1, etc.)
#   - Internet access (to download Atomic Red Team)
#
# SAFETY:
#   - Each test runs a REAL command but cleans up after itself
#   - Windows Defender may block some tests -- that's EXPECTED and GOOD
#     (it proves your security controls work)
#   - All changes are reversible via the -Cleanup flag
#
# USAGE:
#   .\setup_atomic_red_team.ps1              # Install + run all 10 tests
#   .\setup_atomic_red_team.ps1 -InstallOnly # Just install, don't run tests
#   .\setup_atomic_red_team.ps1 -TestOnly    # Skip install, run tests
#   .\setup_atomic_red_team.ps1 -Cleanup     # Remove Atomic Red Team
#
# ============================================================================

param(
    [switch]$InstallOnly,
    [switch]$TestOnly,
    [switch]$Cleanup,
    [switch]$SkipDefenderExclusion
)

$ErrorActionPreference = "Continue"

# -- Colors for output --
function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  [X] $msg" -ForegroundColor Red }

# ============================================================================
# STEP 1: Install Atomic Red Team
# ============================================================================

function Install-ART {
    Write-Step "Installing Atomic Red Team"

    # Add exclusion so Defender doesn't quarantine the test payloads
    if (-not $SkipDefenderExclusion) {
        try {
            $artPath = "C:\AtomicRedTeam"
            Write-Host "  Adding Defender exclusion for $artPath..." -ForegroundColor DarkGray
            Add-MpPreference -ExclusionPath $artPath -ErrorAction Stop
            Write-OK "Defender exclusion added"
        } catch {
            Write-Warn "Could not add Defender exclusion: $($_.Exception.Message)"
            Write-Warn "Some tests may be blocked by Defender (that's okay)"
        }
    }

    # Install the PowerShell module
    try {
        if (-not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
            Write-Host "  Installing Invoke-AtomicRedTeam module..." -ForegroundColor DarkGray
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null
            Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
            Write-OK "Module installed"
        } else {
            Write-OK "Module already installed"
        }
    } catch {
        Write-Fail "Module install failed: $($_.Exception.Message)"
        Write-Host "  Try manually: Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force" -ForegroundColor DarkGray
        return $false
    }

    # Download the atomics (test definitions)
    try {
        if (-not (Test-Path "C:\AtomicRedTeam\atomics")) {
            Write-Host "  Downloading atomic test definitions..." -ForegroundColor DarkGray
            # Download and run the installer script from the official repo
            IEX (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing).Content
            Install-AtomicRedTeam -getAtomics -Force
            Write-OK "Atomics downloaded to C:\AtomicRedTeam"
        } else {
            Write-OK "Atomics already present"
        }
        Import-Module invoke-atomicredteam -Force
    } catch {
        Write-Fail "Atomics download failed: $($_.Exception.Message)"
        Write-Host "  Manual fix: run these two lines in PowerShell as Admin:" -ForegroundColor DarkGray
        Write-Host "    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)" -ForegroundColor DarkGray
        Write-Host "    Install-AtomicRedTeam -getAtomics -Force" -ForegroundColor DarkGray
        return $false
    }

    return $true
}

# ============================================================================
# STEP 2: Run 10 Safe MITRE ATT&CK Tests
# ============================================================================
#
# These 10 tests are chosen because:
#   1. They generate rich Sysmon + PSBL telemetry
#   2. They match our sysmon_translator's 62 MITRE patterns
#   3. They're safe (reversible, no data destruction)
#   4. They cover the 10 attack types in our golden dataset
#

function Run-AttackTests {
    Write-Step "Running 10 MITRE ATT&CK simulation tests"
    Write-Host "  Each test runs a REAL command, Sysmon logs it, your exporters" -ForegroundColor DarkGray
    Write-Host "  capture it, and Vigilis enriches it as a real attack case." -ForegroundColor DarkGray
    Write-Host ""

    Import-Module invoke-atomicredteam -Force -ErrorAction SilentlyContinue

    $tests = @(
        @{
            Technique = "T1059.001"
            Name = "PowerShell Encoded Command"
            Description = "Runs an encoded PowerShell command (benign payload)"
            TestNumber = 1
        },
        @{
            Technique = "T1003.001"
            Name = "LSASS Memory Dump (comsvcs.dll)"
            Description = "Attempts LSASS dump via comsvcs.dll MiniDump"
            TestNumber = 2
        },
        @{
            Technique = "T1053.005"
            Name = "Scheduled Task Creation"
            Description = "Creates a scheduled task for persistence"
            TestNumber = 1
        },
        @{
            Technique = "T1547.001"
            Name = "Registry Run Key Persistence"
            Description = "Adds a Registry Run key for boot persistence"
            TestNumber = 1
        },
        @{
            Technique = "T1105"
            Name = "File Download via certutil"
            Description = "Downloads a file using certutil (LOLBin)"
            TestNumber = 1
        },
        @{
            Technique = "T1087.001"
            Name = "Local Account Discovery"
            Description = "Enumerates local accounts via net user"
            TestNumber = 1
        },
        @{
            Technique = "T1082"
            Name = "System Information Discovery"
            Description = "Collects system info (hostname, OS version)"
            TestNumber = 1
        },
        @{
            Technique = "T1136.001"
            Name = "Local Account Creation"
            Description = "Creates a local user account"
            TestNumber = 1
        },
        @{
            Technique = "T1562.001"
            Name = "Disable Windows Defender"
            Description = "Attempts to disable real-time protection"
            TestNumber = 1
        },
        @{
            Technique = "T1070.001"
            Name = "Windows Event Log Clear"
            Description = "Clears a Windows event log"
            TestNumber = 1
        }
    )

    $passed = 0
    $failed = 0
    $blocked = 0

    foreach ($test in $tests) {
        Write-Host "`n  [$($test.Technique)] $($test.Name)" -ForegroundColor White
        Write-Host "    $($test.Description)" -ForegroundColor DarkGray

        try {
            # Run the atomic test
            Invoke-AtomicTest $test.Technique -TestNumbers $test.TestNumber -Confirm:$false -ErrorAction Stop 2>&1 | Out-Null
            Write-OK "Test executed -- Sysmon should have logged this"
            $passed++

            # Wait a moment for Sysmon to process
            Start-Sleep -Seconds 2

            # Run cleanup to undo changes
            try {
                Invoke-AtomicTest $test.Technique -TestNumbers $test.TestNumber -Cleanup -Confirm:$false -ErrorAction SilentlyContinue 2>&1 | Out-Null
                Write-Host "    Cleanup completed" -ForegroundColor DarkGray
            } catch {
                Write-Warn "Cleanup skipped (may need manual cleanup)"
            }
        } catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "blocked|quarantine|defender|denied") {
                Write-Warn "Blocked by security controls (this is expected and GOOD)"
                $blocked++
            } else {
                Write-Fail "Failed: $errMsg"
                $failed++
            }
        }
    }

    Write-Step "Attack Simulation Complete"
    Write-Host "  Passed: $passed | Blocked by Defender: $blocked | Failed: $failed" -ForegroundColor White
    Write-Host ""
    Write-Host "  Your Vigilis exporters will pick up these events on their next" -ForegroundColor DarkGray
    Write-Host "  scheduled run (every 5 minutes). Check the Cases page after that." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Tip: run the exporters manually for instant results:" -ForegroundColor Yellow
    Write-Host '    & "C:\Tools\SysmonExport\export_sysmon.ps1"' -ForegroundColor Yellow
    Write-Host '    & "C:\Tools\SysmonExport\export_psbl.ps1"' -ForegroundColor Yellow
}

# ============================================================================
# STEP 3: Cleanup
# ============================================================================

function Remove-ART {
    Write-Step "Removing Atomic Red Team"

    try {
        Remove-Module invoke-atomicredteam -Force -ErrorAction SilentlyContinue
        if (Test-Path "C:\AtomicRedTeam") {
            Remove-Item "C:\AtomicRedTeam" -Recurse -Force
            Write-OK "C:\AtomicRedTeam removed"
        }
        Remove-MpPreference -ExclusionPath "C:\AtomicRedTeam" -ErrorAction SilentlyContinue
        Write-OK "Defender exclusion removed"
    } catch {
        Write-Warn "Cleanup issue: $($_.Exception.Message)"
    }
}

# ============================================================================
# MAIN
# ============================================================================

Write-Host ""
Write-Host "  Vigilis Attack Simulation Runner" -ForegroundColor Cyan
Write-Host "  Powered by Atomic Red Team (MITRE ATT&CK)" -ForegroundColor DarkGray
Write-Host ""

if ($Cleanup) {
    Remove-ART
    exit 0
}

if (-not $TestOnly) {
    $ok = Install-ART
    if (-not $ok -and -not $InstallOnly) {
        Write-Fail "Installation failed. Fix the errors above and retry."
        exit 1
    }
}

if (-not $InstallOnly) {
    Run-AttackTests
}

Write-Host ""
Write-Host "  Done! Check http://localhost:8000/demo/ui/cases for new attack cases." -ForegroundColor Green
Write-Host ""
