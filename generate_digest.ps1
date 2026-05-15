param(
    [int]$Days = 7,
    [switch]$NoLlm,
    [switch]$Pdf
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Virtual environment not found. Running setup first..." -ForegroundColor Yellow
    & ".\setup.ps1"
}

$argsList = @("-m", "secops", "digest", "--days", "$Days")
if ($NoLlm) {
    $argsList += "--no-llm"
}
if ($Pdf) {
    $argsList += "--pdf"
}

Write-Host "Generating threat digest for the last $Days day(s)..." -ForegroundColor Cyan
& ".\.venv\Scripts\python.exe" @argsList

