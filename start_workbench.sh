#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

HOST_NAME="127.0.0.1"
PORT="8765"
NO_OPEN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --no-open) NO_OPEN=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ ! -x ".venv/bin/python" ]; then
  echo "Virtual environment not found. Running setup first..."
  ./setup.sh
fi

ARGS=(-m secops web --host "$HOST_NAME" --port "$PORT")
if [ "$NO_OPEN" -eq 1 ]; then
  ARGS+=(--no-open)
fi

echo "Starting SecOps Workbench at http://$HOST_NAME:$PORT/"
exec ./.venv/bin/python "${ARGS[@]}"

