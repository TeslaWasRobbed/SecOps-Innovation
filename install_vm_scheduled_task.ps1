param(
    [string]$TaskName = "SecOpsInnovationWorkbench",
    [string]$HostName = "0.0.0.0",
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$ScriptPath = Join-Path $ProjectRoot "run_workbench_service.ps1"
if (-not (Test-Path $ScriptPath)) {
    throw "Could not find $ScriptPath"
}

New-Item -ItemType Directory -Force -Path "logs" | Out-Null

$argument = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -HostName $HostName -Port $Port"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument -WorkingDirectory $ProjectRoot
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DisallowStartIfOnBatteries:$false -ExecutionTimeLimit (New-TimeSpan -Days 365) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Runs the SecOps Innovation browser workbench on VM startup." -Force | Out-Null

Write-Host "Installed scheduled task: $TaskName" -ForegroundColor Green
Write-Host "Start now with:"
Write-Host "  Start-ScheduledTask -TaskName `"$TaskName`""
Write-Host "Check logs:"
Write-Host "  logs\workbench-service.log"

