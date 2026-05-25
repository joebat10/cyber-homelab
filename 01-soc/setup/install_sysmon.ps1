#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Downloads and installs Sysmon with the SwiftOnSecurity configuration.
.DESCRIPTION
    - Downloads Sysmon from Microsoft Sysinternals
    - Downloads SwiftOnSecurity sysmon-config (community best-practice config)
    - Installs Sysmon64 with the config
    - Verifies the service is running
    - Optionally uses local config from 01-soc/configs/sysmon_config.xml
.PARAMETER UseLocalConfig
    Use the local sysmon_config.xml from the repo instead of downloading
    SwiftOnSecurity's config from GitHub
.EXAMPLE
    .\install_sysmon.ps1
    .\install_sysmon.ps1 -UseLocalConfig
#>

param(
    [switch]$UseLocalConfig
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = 'SilentlyContinue'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n[STEP] $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "[OK]   $msg"   -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg"   -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[FAIL] $msg"   -ForegroundColor Red; exit 1 }

# ── Constants ─────────────────────────────────────────────────────────────────
$SysmonZipUrl   = "https://download.sysinternals.com/files/Sysmon.zip"
$SwiftConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

$TempDir        = Join-Path $env:TEMP "sysmon_install"
$SysmonZip      = Join-Path $TempDir  "Sysmon.zip"
$SysmonDir      = Join-Path $TempDir  "Sysmon"
$ConfigPath     = Join-Path $TempDir  "sysmon_config.xml"

# ── Header ────────────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Sysmon Installer (SwiftOnSecurity)"     -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ── Preflight ─────────────────────────────────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Run this script as Administrator"
}

New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# ── Step 1: Download Sysmon ───────────────────────────────────────────────────
Write-Step "Step 1/4 — Downloading Sysmon from Sysinternals"

# Check if already running
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Warn "Sysmon64 already running — will update config only"
    $UpdateOnly = $true
} else {
    $UpdateOnly = $false
}

if (-not $UpdateOnly) {
    try {
        Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $SysmonZip -UseBasicParsing
        Write-OK "Downloaded Sysmon.zip ($([Math]::Round((Get-Item $SysmonZip).Length/1KB))KB)"
    } catch {
        Write-Fail "Download failed: $_ `nCheck internet connectivity."
    }

    # Extract
    if (Test-Path $SysmonDir) { Remove-Item $SysmonDir -Recurse -Force }
    Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
    Write-OK "Extracted to: $SysmonDir"

    # Verify binary
    $Sysmon64 = Join-Path $SysmonDir "Sysmon64.exe"
    if (-not (Test-Path $Sysmon64)) {
        Write-Fail "Sysmon64.exe not found in archive — unexpected archive structure"
    }
    Write-OK "Sysmon64.exe found: $(& $Sysmon64 -? 2>&1 | Select-String 'v\d' | Select-Object -First 1)"
}

# ── Step 2: Get configuration ─────────────────────────────────────────────────
Write-Step "Step 2/4 — Getting Sysmon configuration"

if ($UseLocalConfig) {
    # Look for local config relative to script location
    $scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
    $localConfig = Join-Path $scriptDir "..\configs\sysmon_config.xml"
    $localConfig = [System.IO.Path]::GetFullPath($localConfig)

    if (Test-Path $localConfig) {
        Copy-Item $localConfig $ConfigPath -Force
        Write-OK "Using local config: $localConfig"
    } else {
        Write-Warn "Local config not found at $localConfig — falling back to SwiftOnSecurity"
        $UseLocalConfig = $false
    }
}

if (-not $UseLocalConfig) {
    Write-Host "  Downloading SwiftOnSecurity sysmon-config..."
    try {
        Invoke-WebRequest -Uri $SwiftConfigUrl -OutFile $ConfigPath -UseBasicParsing
        Write-OK "Downloaded SwiftOnSecurity config ($([Math]::Round((Get-Item $ConfigPath).Length/1KB))KB)"
    } catch {
        Write-Fail "Config download failed: $_"
    }
}

# ── Step 3: Install or update ─────────────────────────────────────────────────
Write-Step "Step 3/4 — Installing Sysmon64"

$Sysmon64 = Join-Path $SysmonDir "Sysmon64.exe"

if ($UpdateOnly) {
    # Just update the config on the running instance
    $SystemSysmon = "C:\Windows\Sysmon64.exe"
    if (-not (Test-Path $SystemSysmon)) {
        $SystemSysmon = (Get-Command Sysmon64.exe -ErrorAction SilentlyContinue)?.Source
    }
    if ($SystemSysmon) {
        Write-Host "  Updating config on existing installation..."
        & $SystemSysmon -c $ConfigPath
        Write-OK "Config updated"
    } else {
        Write-Warn "Could not find system Sysmon64.exe — skipping config update"
    }
} else {
    # Fresh install
    Write-Host "  Running: Sysmon64.exe -accepteula -i <config>"
    $proc = Start-Process -FilePath $Sysmon64 `
        -ArgumentList "-accepteula", "-i", $ConfigPath `
        -Wait -PassThru -NoNewWindow

    if ($proc.ExitCode -ne 0) {
        Write-Fail "Sysmon installation failed (exit code $($proc.ExitCode))"
    }
    Write-OK "Sysmon64 installed"
}

# ── Step 4: Verify ────────────────────────────────────────────────────────────
Write-Step "Step 4/4 — Verifying installation"

Start-Sleep -Seconds 3

$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Fail "Sysmon64 service not found — installation may have failed"
}

if ($svc.Status -ne "Running") {
    Start-Service -Name "Sysmon64"
    Start-Sleep -Seconds 2
    $svc.Refresh()
}

if ($svc.Status -eq "Running") {
    Write-OK "Sysmon64 service: Running"
} else {
    Write-Fail "Sysmon64 service not running (status: $($svc.Status))"
}

# Set to auto-start
Set-Service -Name "Sysmon64" -StartupType Automatic
Write-OK "Service startup: Automatic"

# Check event log channel is available
$eventLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
if ($eventLog) {
    Write-OK "Event log channel: Microsoft-Windows-Sysmon/Operational (enabled)"
} else {
    Write-Warn "Event log channel not found — Sysmon may need a reboot"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Sysmon Installation Complete"             -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Service : Sysmon64 — $($svc.Status)"
Write-Host "  Config  : $ConfigPath (active)"
Write-Host "  Events  : Event Viewer → Microsoft-Windows-Sysmon/Operational"
Write-Host ""
Write-Host "  Monitored event IDs (key ones):"  -ForegroundColor Yellow
Write-Host "    Event 1  — Process Create"
Write-Host "    Event 3  — Network Connection"
Write-Host "    Event 7  — Image/DLL Loaded"
Write-Host "    Event 10 — Process Access (LSASS monitoring)"
Write-Host "    Event 11 — File Created"
Write-Host "    Event 12/13 — Registry Events"
Write-Host "    Event 22 — DNS Query"
Write-Host ""
Write-Host "  Wazuh will collect these via the Windows agent." -ForegroundColor Cyan
Write-Host "  Make sure the Wazuh agent is installed and running." -ForegroundColor Cyan
