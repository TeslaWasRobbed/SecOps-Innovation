#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

SKIP_INSTALL=0
for arg in "$@"; do
  case "$arg" in
    --skip-install) SKIP_INSTALL=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

echo "==> Checking Python"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 was not found. Install Python 3.11+ first." >&2
  exit 1
fi
"$PYTHON_BIN" --version

echo "==> Creating virtual environment"
if [ ! -d ".venv" ]; then
  "$PYTHON_BIN" -m venv .venv
else
  echo ".venv already exists"
fi

VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python"
if [ ! -x "$VENV_PYTHON" ]; then
  echo "Virtual environment Python not found at $VENV_PYTHON" >&2
  exit 1
fi

if [ "$SKIP_INSTALL" -eq 0 ]; then
  echo "==> Installing Python dependencies"
  "$VENV_PYTHON" -m pip install --upgrade pip
  "$VENV_PYTHON" -m pip install -r requirements.txt
else
  echo "Skipping dependency install"
fi

echo "==> Creating local configuration files"
if [ ! -f ".env" ]; then
  if [ -f ".env.example" ]; then
    cp .env.example .env
    echo "Created .env from .env.example"
  else
    touch .env
    echo "Created empty .env"
  fi
else
  echo ".env already exists"
fi

if [ ! -f "company_profile.yaml" ] && [ -f "company_profile.example.yaml" ]; then
  cp company_profile.example.yaml company_profile.yaml
  echo "Created company_profile.yaml from example"
else
  echo "company_profile.yaml already exists"
fi

echo "==> Creating output folders"
mkdir -p output/threat_digest output/actor_watch output/detections/drafts logs

echo "==> Running import check"
"$VENV_PYTHON" -m compileall secops threat_digest actor_watch detection shared

echo "==> Setup complete"
echo "Next steps:"
echo "1. Edit .env and add Azure OpenAI or Anthropic values."
echo "2. Edit company_profile.yaml if needed."
echo "3. Generate a digest: ./generate_digest.sh"
echo "4. Start the browser workbench: ./start_workbench.sh"

