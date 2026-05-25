#!/bin/bash
# Ingest a JSONL file of Bumblebee simulated/real events into SentinelOne
# Singularity Data Lake via the `uploadLogs` API endpoint.
#
# Required env:
#   SDL_TOKEN   SDL Log Write key (Settings -> API Tokens -> SDL Log Write)
#
# Optional env:
#   SDL_HOST    e.g. "xdr.us1.sentinelone.net"  (default; override per tenant)
#   SDL_PARSER  parser name to apply (default: json) — leave at json for
#               line-per-record JSONL ingestion
#   SDL_SOURCE  logical source name shown as dataSource.name in SDL
#               (default: bumblebee-simulated)
#
# Usage:
#   SDL_TOKEN=xxx ./ingest_to_sdl.sh simulated_exposure.jsonl
#   SDL_TOKEN=xxx SDL_SOURCE=bumblebee-real ./ingest_to_sdl.sh real_findings.jsonl
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <path-to-jsonl> [extra-curl-args...]" >&2
    exit 2
fi

INPUT="$1"; shift || true
[ -r "$INPUT" ] || { echo "ERROR: cannot read $INPUT" >&2; exit 3; }
[ -n "${SDL_TOKEN:-}" ] || { echo "ERROR: SDL_TOKEN env var is required" >&2; exit 4; }

SDL_HOST="${SDL_HOST:-xdr.us1.sentinelone.net}"
SDL_PARSER="${SDL_PARSER:-json}"
SDL_SOURCE="${SDL_SOURCE:-bumblebee-simulated}"

URL="https://${SDL_HOST}/api/uploadLogs"

# uploadLogs accepts the body verbatim; for JSONL, the parser must be 'json'
# (each line is parsed as an event). Query params identify the source.
echo "POST $URL  parser=$SDL_PARSER  source=$SDL_SOURCE  bytes=$(wc -c < "$INPUT")" >&2

curl --fail-with-body -sS -X POST \
     -H "Authorization: Bearer ${SDL_TOKEN}" \
     -H "Content-Type: application/json" \
     --data-binary "@${INPUT}" \
     "${URL}?parser=${SDL_PARSER}&host=${SDL_SOURCE}&logfile=${SDL_SOURCE}" \
     "$@"

echo
echo "Upload complete. Query in SDL with:"
echo "  RecordType='BumblebeeSimulatedExposure' | group c=count() by catalog | sort -c"
