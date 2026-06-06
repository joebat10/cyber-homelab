param(
    [string]$ManagerIP    = "192.168.56.10",
    [string]$AgentName    = $env:COMPUTERNAME,
    [string]$WazuhVersion = "4.9.2"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$MsiName = "wazuh-agent-$WazuhVersion-1.msi"
$MsiUrl  = "https://packages.wazuh.com/4.x/windows/$MsiName"
$MsiPath = "$env:TEMP\$MsiName"
$LogPath = "$env:TEMP\wazuh_install.log"

Write-Host ""
Write-Host "  Wazuh Agent Installer" -ForegroundColor Cyan
Write-Host "  Manager : $ManagerIP" -ForegroundColor Cyan
Write-Host "  Agent   : $AgentName" -ForegroundColor Cyan
Write-Host "  Version : $WazuhVersion" -ForegroundColor Cyan
Write-Host ""

# Download
Write-Host "[1/3] Downloading $MsiName..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
Write-Host "      Saved to: $MsiPath" -ForegroundColor Green

# Install — single quoted string avoids array/quoting bugs with Start-Process
Write-Host "[2/3] Installing silently..." -ForegroundColor Cyan
$msiArgs = "/i `"$MsiPath`" /qn WAZUH_MANAGER=$ManagerIP WAZUH_AGENT_NAME=$AgentName WAZUH_REGISTRATION_SERVER=$ManagerIP /l*v `"$LogPath`""
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Host "      msiexec failed (exit $($proc.ExitCode)). Log: $LogPath" -ForegroundColor Red
    exit 1
}
Write-Host "      Installed to C:\Program Files (x86)\ossec-agent\" -ForegroundColor Green

# Start service
Write-Host "[3/3] Starting WazuhSvc..." -ForegroundColor Cyan
Start-Sleep -Seconds 3
Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue
Set-Service  -Name WazuhSvc -StartupType Automatic

$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
$svcColor = if ($svc.Status -eq "Running") { "Green" } else { "Yellow" }
Write-Host "      WazuhSvc: $($svc.Status)" -ForegroundColor $svcColor

# Port check
$tcp = Test-NetConnection -ComputerName $ManagerIP -Port 1514 -WarningAction SilentlyContinue
$portColor = if ($tcp.TcpTestSucceeded) { "Green" } else { "Red" }
Write-Host "      Port 1514 reachable: $($tcp.TcpTestSucceeded)" -ForegroundColor $portColor
if (-not $tcp.TcpTestSucceeded) {
    Write-Host "      On the Wazuh manager run: sudo ufw allow 1514/tcp && sudo ufw allow 1515/tcp" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Done. Check logs: $LogPath" -ForegroundColor Green
Write-Host "  Agent log: C:\Program Files (x86)\ossec-agent\ossec.log"
Write-Host ""
