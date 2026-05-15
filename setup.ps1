param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-PythonCommand {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return "python"
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return "py -3"
    }
    throw "Python was not found. Install Python 3.11+ and tick 'Add python.exe to PATH'."
}

Write-Step "Checking Python"
$PythonCommand = Get-PythonCommand
Write-Host "Using: $PythonCommand"

Write-Step "Creating virtual environment"
if (-not (Test-Path ".venv")) {
    Invoke-Expression "$PythonCommand -m venv .venv"
} else {
    Write-Host ".venv already exists"
}

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment Python not found at $VenvPython"
}

if (-not $SkipInstall) {
    Write-Step "Installing Python dependencies"
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -r requirements.txt
} else {
    Write-Host "Skipping dependency install"
}

Write-Step "Creating local configuration files"
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "Created .env from .env.example"
    } else {
        New-Item -Path ".env" -ItemType File | Out-Null
        Write-Host "Created empty .env"
    }
} else {
    Write-Host ".env already exists"
}

if (-not (Test-Path "company_profile.yaml")) {
    if (Test-Path "company_profile.example.yaml") {
        Copy-Item "company_profile.example.yaml" "company_profile.yaml"
        Write-Host "Created company_profile.yaml from example"
    }
} else {
    Write-Host "company_profile.yaml already exists"
}

Write-Step "Creating output folders"
New-Item -ItemType Directory -Force -Path "output\threat_digest", "output\actor_watch", "output\detections\drafts" | Out-Null

Write-Step "Running import check"
& $VenvPython -m compileall secops threat_digest actor_watch detection shared

Write-Step "Setup complete"
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "1. Edit .env and add your Azure OpenAI values:"
Write-Host "   AZURE_OPENAI_ENDPOINT"
Write-Host "   AZURE_OPENAI_KEY"
Write-Host "   AZURE_OPENAI_DEPLOYMENT"
Write-Host "2. Edit company_profile.yaml if needed."
Write-Host "3. Generate a digest:"
Write-Host "   .\generate_digest.ps1"
Write-Host "4. Start the browser workbench:"
Write-Host "   .\start_workbench.ps1"

