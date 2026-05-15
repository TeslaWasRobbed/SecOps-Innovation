#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

DAYS=7
NO_LLM=0
PDF=0

while [ $# -gt 0 ]; do
  case "$1" in
    --days) DAYS="$2"; shift 2 ;;
    --no-llm) NO_LLM=1; shift ;;
    --pdf) PDF=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ ! -x ".venv/bin/python" ]; then
  echo "Virtual environment not found. Running setup first..."
  ./setup.sh
fi

ARGS=(-m secops digest --days "$DAYS")
if [ "$NO_LLM" -eq 1 ]; then
  ARGS+=(--no-llm)
fi
if [ "$PDF" -eq 1 ]; then
  ARGS+=(--pdf)
fi

echo "Generating threat digest for the last $DAYS day(s)..."
exec ./.venv/bin/python "${ARGS[@]}"

