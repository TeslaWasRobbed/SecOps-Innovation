param(
    [string]$HostName = "0.0.0.0",
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

New-Item -ItemType Directory -Force -Path "logs" | Out-Null
$LogPath = Join-Path $ProjectRoot "logs\workbench-service.log"

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format o) $Message"
    Add-Content -Path $LogPath -Value $line
}

try {
    Write-Log "Starting SecOps Workbench on $HostName`:$Port"
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        Write-Log "Virtual environment missing; running setup."
        & ".\setup.ps1" | ForEach-Object { Write-Log $_ }
    }
    & ".\.venv\Scripts\python.exe" -m secops web --host $HostName --port $Port --no-open *>> $LogPath
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)"
    throw
}

