#!/bin/bash
# Deploy bumblebee_dashboard.json to SentinelOne Singularity Data Lake via the
# configuration-file (`putFile`) endpoint.
#
# Required env:
#   SDL_TOKEN   SDL Config Write key (Settings -> API Tokens -> SDL Config Write)
#
# Optional env:
#   SDL_HOST    e.g. xdr.us1.sentinelone.net (default)
#   DASH_PATH   SDL config file path (default: /dashboards/bumblebee-exposure)
#
# Usage:
#   SDL_TOKEN=xxx ./deploy_dashboard.sh
#   SDL_TOKEN=xxx DASH_PATH=/dashboards/my-bumblebee ./deploy_dashboard.sh
set -euo pipefail

SDL_HOST="${SDL_HOST:-xdr.us1.sentinelone.net}"
DASH_PATH="${DASH_PATH:-/dashboards/bumblebee-exposure}"
DASH_FILE="$(dirname "$0")/bumblebee_dashboard.json"

[ -r "$DASH_FILE" ] || { echo "ERROR: cannot read $DASH_FILE" >&2; exit 2; }
[ -n "${SDL_TOKEN:-}" ] || { echo "ERROR: SDL_TOKEN env var required" >&2; exit 3; }

# Validate JSON locally first
python3 -c "import json,sys; json.load(open('$DASH_FILE'))" \
  || { echo "ERROR: $DASH_FILE is not valid JSON" >&2; exit 4; }

URL="https://${SDL_HOST}/api/config${DASH_PATH}"
echo "PUT $URL" >&2

# putFile uses POST with the file body
curl --fail-with-body -sS -X POST \
     -H "Authorization: Bearer ${SDL_TOKEN}" \
     -H "Content-Type: application/json" \
     --data-binary "@${DASH_FILE}" \
     "$URL"

echo
echo "Sleeping 3s for eventual consistency..."
sleep 3

echo "Verifying deploy..."
curl --fail-with-body -sS -X GET \
     -H "Authorization: Bearer ${SDL_TOKEN}" \
     "$URL" | head -c 400
echo
echo
echo "Dashboard available in SDL at: $DASH_PATH"
