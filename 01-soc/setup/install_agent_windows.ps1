#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs and registers the Wazuh agent on Windows.
.DESCRIPTION
    Downloads the Wazuh agent MSI, installs it silently with the specified
    manager IP, starts the service, and verifies connectivity.
.PARAMETER ManagerIP
    IP address of the Wazuh Manager (default: 192.168.56.10)
.PARAMETER AgentName
    Name to register this agent as (default: hostname)
.PARAMETER WazuhVersion
    Wazuh agent version to download (default: 4.9.0)
.EXAMPLE
    .\install_agent_windows.ps1
    .\install_agent_windows.ps1 -ManagerIP 192.168.56.10 -AgentName "WIN11-LAB"
#>

param(
    [string]$ManagerIP   = "192.168.56.10",
    [string]$AgentName   = $env:COMPUTERNAME,
    [string]$WazuhVersion = "4.9.2"
)

$ErrorActionPreference = "Stop"

# ── Helper functions ──────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n[STEP] $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "[OK]   $msg"   -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg"   -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[FAIL] $msg"   -ForegroundColor Red; exit 1 }

# ── Preflight ─────────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Wazuh Agent Installer for Windows"      -ForegroundColor Cyan
Write-Host "  Manager : $ManagerIP"                   -ForegroundColor Cyan
Write-Host "  Agent   : $AgentName"                   -ForegroundColor Cyan
Write-Host "  Version : $WazuhVersion"                -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check admin
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Run this script as Administrator"
}

# Ping manager
Write-Step "Checking connectivity to Wazuh Manager ($ManagerIP)"
if (Test-Connection -ComputerName $ManagerIP -Count 2 -Quiet) {
    Write-OK "Manager is reachable"
} else {
    Write-Warn "Cannot ping $ManagerIP — VM may block ICMP. Continuing..."
}

# ── Step 1: Download agent MSI ────────────────────────────────────────────────
Write-Step "Step 1/4 — Downloading Wazuh agent $WazuhVersion"

$MsiName   = "wazuh-agent-$WazuhVersion-1.msi"
$MsiUrl    = "https://packages.wazuh.com/4.x/windows/$MsiName"
$MsiPath   = Join-Path $env:TEMP $MsiName

if (Test-Path $MsiPath) {
    Write-Warn "Installer already exists at $MsiPath — skipping download"
} else {
    try {
        Write-Host "  Downloading from: $MsiUrl"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
        Write-OK "Downloaded: $MsiPath ($([Math]::Round((Get-Item $MsiPath).Length/1MB, 1)) MB)"
    } catch {
        Write-Fail "Download failed: $_"
    }
}

# ── Step 2: Uninstall existing agent (if any) ─────────────────────────────────
Write-Step "Step 2/4 — Checking for existing installation"

$existing = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warn "Existing Wazuh agent found — removing..."
    Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
    $existingMsi = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*Wazuh*" }
    if ($existingMsi) {
        $existingMsi.Uninstall() | Out-Null
        Write-OK "Previous version uninstalled"
    }
    Start-Sleep -Seconds 3
} else {
    Write-OK "No existing installation found"
}

# ── Step 3: Silent install ────────────────────────────────────────────────────
Write-Step "Step 3/4 — Installing Wazuh agent (silent)"

$InstallArgs = @(
    "/i", $MsiPath,
    "/q",
    "WAZUH_MANAGER=`"$ManagerIP`"",
    "WAZUH_AGENT_NAME=`"$AgentName`"",
    "WAZUH_REGISTRATION_SERVER=`"$ManagerIP`"",
    "/l*v", (Join-Path $env:TEMP "wazuh_agent_install.log")
)

Write-Host "  Running: msiexec $($InstallArgs -join ' ')"
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $InstallArgs -Wait -PassThru

if ($proc.ExitCode -ne 0) {
    Write-Warn "msiexec exit code $($proc.ExitCode)"
    Write-Warn "Check log: $env:TEMP\wazuh_agent_install.log"
    Write-Fail "Installation failed (exit code $($proc.ExitCode))"
}
Write-OK "Agent installed to C:\Program Files (x86)\ossec-agent\"

# ── Step 4: Start service and verify ─────────────────────────────────────────
Write-Step "Step 4/4 — Starting Wazuh agent service"

# Give install a moment to finalise
Start-Sleep -Seconds 5

try {
    Start-Service -Name "WazuhSvc"
    Start-Sleep -Seconds 3

    $svc = Get-Service -Name "WazuhSvc"
    if ($svc.Status -eq "Running") {
        Write-OK "WazuhSvc is running"
    } else {
        Write-Warn "Service status: $($svc.Status)"
        Write-Warn "Check: C:\Program Files (x86)\ossec-agent\ossec.log"
    }
} catch {
    Write-Warn "Could not start service: $_ — may need manual start"
}

# Set service to auto-start on boot
Set-Service -Name "WazuhSvc" -StartupType Automatic
Write-OK "Service set to Automatic startup"

# ── Verify connection to manager ─────────────────────────────────────────────
Write-Host "`n[CHECK] Testing connection to manager on port 1514..."
$tcpTest = Test-NetConnection -ComputerName $ManagerIP -Port 1514 -WarningAction SilentlyContinue
if ($tcpTest.TcpTestSucceeded) {
    Write-OK "Port 1514 open — agent can reach manager"
} else {
    Write-Warn "Port 1514 not reachable — check VM firewall / ufw rules"
    Write-Warn "On Wazuh Manager run: sudo ufw allow 1514/tcp"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Wazuh Agent Installation Complete"      -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Agent name   : $AgentName"
Write-Host "  Manager IP   : $ManagerIP"
Write-Host "  Service      : $(if ((Get-Service WazuhSvc -EA SilentlyContinue).Status -eq 'Running') {'Running'} else {'Stopped - check logs'})"
Write-Host "  Config file  : C:\Program Files (x86)\ossec-agent\ossec.conf"
Write-Host "  Log file     : C:\Program Files (x86)\ossec-agent\ossec.log"
Write-Host ""
Write-Host "  To check registration on the manager:" -ForegroundColor Yellow
Write-Host "    ssh user@$ManagerIP"
Write-Host "    sudo /var/ossec/bin/agent_control -l"
Write-Host ""
Write-Host "  Install log  : $env:TEMP\wazuh_agent_install.log"
