param(
    [switch]$ClearOutput,
    [switch]$ClearVenv
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host "Cleaning transient workspace files..." -ForegroundColor Cyan

$cacheDirs = Get-ChildItem -Path $ProjectRoot -Recurse -Directory -Force |
    Where-Object {
        $_.FullName -notlike "*\.venv\*" -and
        $_.Name -in @("__pycache__", ".pytest_cache")
    }

foreach ($dir in $cacheDirs) {
    Write-Host "Removing $($dir.FullName)"
    Remove-Item -LiteralPath $dir.FullName -Recurse -Force
}

if (Test-Path ".cache") {
    Write-Host "Removing .cache"
    Remove-Item -LiteralPath ".cache" -Recurse -Force
}

if ($ClearOutput -and (Test-Path "output")) {
    Write-Host "Removing generated output"
    Remove-Item -LiteralPath "output" -Recurse -Force
    New-Item -ItemType Directory -Force -Path "output\threat_digest", "output\actor_watch", "output\detections\drafts" | Out-Null
}

if ($ClearVenv -and (Test-Path ".venv")) {
    Write-Host "Removing local virtual environment"
    Remove-Item -LiteralPath ".venv" -Recurse -Force
}

Write-Host "Workspace cleanup complete." -ForegroundColor Green

