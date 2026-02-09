#!/usr/bin/env bash
# Run this INSIDE the ingestion container when juiceshop is STOPPED to see what curl returns.
# From host: docker compose exec ingestion /app/scripts/test-juice-health-from-ingestion.sh
set -euo pipefail

HEALTH_URL="${JUICE_URL:-http://juiceshop:3000}"
echo "Probing $HEALTH_URL (juiceshop should be stopped)..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 5 "$HEALTH_URL" 2>/dev/null) || true
echo "HTTP code: ${CODE:-'(empty/curl failed)'}"
if [[ "${CODE:-000}" == "200" ]]; then
  echo "Result: UP (expected DOWN when juiceshop is stopped - check Docker network)"
  exit 1
else
  echo "Result: DOWN (correct - next ingestion cycle will write juice-shop red)"
  exit 0
fi
