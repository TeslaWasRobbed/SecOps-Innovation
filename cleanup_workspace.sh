#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

CLEAR_OUTPUT=0
CLEAR_VENV=0

while [ $# -gt 0 ]; do
  case "$1" in
    --clear-output) CLEAR_OUTPUT=1; shift ;;
    --clear-venv) CLEAR_VENV=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

echo "Cleaning transient workspace files..."
find . -path './.venv' -prune -o -type d \( -name '__pycache__' -o -name '.pytest_cache' \) -print -exec rm -rf {} +
rm -rf .cache

if [ "$CLEAR_OUTPUT" -eq 1 ]; then
  rm -rf output
  mkdir -p output/threat_digest output/actor_watch output/detections/drafts
fi

if [ "$CLEAR_VENV" -eq 1 ]; then
  rm -rf .venv
fi

echo "Workspace cleanup complete."

