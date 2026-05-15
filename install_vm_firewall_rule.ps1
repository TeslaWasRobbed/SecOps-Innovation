param(
    [int]$Port = 8765,
    [string]$DisplayName = "SecOps Innovation Workbench"
)

$ErrorActionPreference = "Stop"

$existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Firewall rule already exists: $DisplayName" -ForegroundColor Yellow
    return
}

New-NetFirewallRule `
    -DisplayName $DisplayName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort $Port `
    -Profile Domain,Private `
    | Out-Null

Write-Host "Created Windows Firewall rule for TCP port $Port" -ForegroundColor Green

