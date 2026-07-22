#!/usr/bin/env bash
# Wrapper for the systemd timer: generates the automated daily briefing.
# Reads optional overrides from .env (DIGEST_SCHEDULE_DAYS, DIGEST_SCHEDULE_PDF)
# without disturbing the app's own dotenv loading.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

DAYS="${DIGEST_SCHEDULE_DAYS:-1}"
ARGS=(--days "$DAYS")
if [ "${DIGEST_SCHEDULE_PDF:-0}" = "1" ]; then
  ARGS+=(--pdf)
fi

echo "[$(date -u +%FT%TZ)] Starting scheduled daily briefing (--days $DAYS)"
./generate_digest.sh "${ARGS[@]}"
echo "[$(date -u +%FT%TZ)] Scheduled daily briefing complete"
