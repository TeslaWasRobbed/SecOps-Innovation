param(
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8765,
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Virtual environment not found. Running setup first..." -ForegroundColor Yellow
    & ".\setup.ps1"
}

function Test-PortOpen {
    param([string]$HostToCheck, [int]$PortToCheck)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connectHost = if ($HostToCheck -eq "0.0.0.0") { "127.0.0.1" } else { $HostToCheck }
        $async = $client.BeginConnect($connectHost, $PortToCheck, $null, $null)
        $connected = $async.AsyncWaitHandle.WaitOne(250, $false)
        if ($connected) {
            $client.EndConnect($async)
        }
        $client.Close()
        return $connected
    } catch {
        return $false
    }
}

if (Test-PortOpen -HostToCheck $HostName -PortToCheck $Port) {
    $displayHost = if ($HostName -eq "0.0.0.0") { "127.0.0.1" } else { $HostName }
    $url = "http://$displayHost`:$Port/"
    Write-Host "Workbench already appears to be running at $url" -ForegroundColor Yellow
    if (-not $NoOpen) {
        Start-Process $url
    }
    return
}

$argsList = @("-m", "secops", "web", "--host", "$HostName", "--port", "$Port")
if ($NoOpen) {
    $argsList += "--no-open"
}

Write-Host "Starting SecOps Workbench at http://$HostName`:$Port/" -ForegroundColor Cyan
& ".\.venv\Scripts\python.exe" @argsList
