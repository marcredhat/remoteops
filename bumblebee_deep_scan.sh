#!/bin/bash
# Bumblebee deep + full-catalog supply-chain exposure scan (RHEL 10 / RemoteOps)
#
# - Runs bumblebee with --profile deep against system-wide roots
# - Pulls EVERY exposure catalog from
#   https://github.com/perplexityai/bumblebee/tree/main/threat_intel
#   and scans each one (catalogs may differ in schema_version, so they are
#   scanned individually rather than via --exposure-catalog <dir>)
# - Writes outputs to $S1_OUTPUT_DIR_PATH (Agent-provided) with fallbacks,
#   using .jsonl / .csv / .json extensions so RemoteOps forwards them to
#   Singularity Data Lake natively
# - Honors $S1_XDR_OUTPUT_FILE_PATH for the dataset.json summary
set -uo pipefail

# RemoteOps runs as a service with a minimal environment; provide sane defaults
# so 'set -u' does not abort on unset HOME/USER/PATH.
: "${HOME:=$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)}"
: "${HOME:=/tmp}"
: "${USER:=$(id -un 2>/dev/null || echo remoteops)}"
: "${PATH:=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
export HOME USER PATH

# CLI flags
ADD_DATE=false
for arg in "$@"; do
    case "$arg" in
        --add-date) ADD_DATE=true ;;
    esac
done

test_is_remote_ops() { [ -n "${S1_OUTPUT_DIR_PATH:-}" ]; }

# Endpoint metadata, computed once and embedded in every record
HOSTNAME_VAL="$(hostname 2>/dev/null || echo unknown)"
OS_ID="linux"; OS_VERSION=""
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-linux}"
    OS_VERSION="${VERSION_ID:-}"
fi
OS_BUILD="$(uname -r 2>/dev/null || echo unknown)"
OS_ARCH="$(uname -m 2>/dev/null || echo unknown)"
COLLECTION_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_UTC="$COLLECTION_UTC"

echo "===== RemoteOps: bumblebee deep exposure scan ====="
uname -a
id
echo "start_utc=$START_UTC"
if test_is_remote_ops; then
    echo "context=RemoteOps (S1_OUTPUT_DIR_PATH is set)"
else
    echo "context=interactive"
fi

# ---------- output dir (SentinelOne RemoteOps convention) ----------
# Pick a directory we can actually write to.
# Order: $S1_OUTPUT_DIR_PATH -> /opt/sentinelone/rso/ -> $HOME/bumblebee-rso/ -> $(pwd)/
tryDir() {
    local d="$1"
    [ -z "$d" ] && return 1
    case "$d" in */) : ;; *) d="${d}/" ;; esac
    mkdir -p "$d" 2>/dev/null || return 1
    local probe="${d}.bumblebee_write_test.$$"
    if ( : > "$probe" ) 2>/dev/null; then
        rm -f "$probe"
        resultOutputDir="$d"
        return 0
    fi
    return 1
}

setResultOutputDir() {
    resultOutputDir=""
    tryDir "${S1_OUTPUT_DIR_PATH:-}" \
      || tryDir "/opt/sentinelone/rso/" \
      || tryDir "$HOME/bumblebee-rso/" \
      || tryDir "$(pwd)/" \
      || { echo "ERROR: no writable output dir found"; exit 5; }
    echo "Script output directory is: $resultOutputDir"
}

setDataSetFilePath() {
    datasetFilePath="${resultOutputDir}dataset.json"
    if [ -n "${S1_XDR_OUTPUT_FILE_PATH:-}" ]; then
        if mkdir -p "$(dirname "$S1_XDR_OUTPUT_FILE_PATH")" 2>/dev/null \
           && : > "${S1_XDR_OUTPUT_FILE_PATH}.test.$$" 2>/dev/null; then
            rm -f "${S1_XDR_OUTPUT_FILE_PATH}.test.$$"
            datasetFilePath="$S1_XDR_OUTPUT_FILE_PATH"
        else
            echo "WARN: S1_XDR_OUTPUT_FILE_PATH not writable, using ${datasetFilePath}"
        fi
    fi
    echo "XDR json output file path: $datasetFilePath"
}

setResultOutputDir
setDataSetFilePath

OUT_DIR="$resultOutputDir"
WORK_DIR="$(mktemp -d -t bumblebee-XXXXXX)"
CATALOG_DIR="$WORK_DIR/threat_intel"
FINDINGS_DIR="${OUT_DIR}findings"
mkdir -p "$CATALOG_DIR" "$FINDINGS_DIR" \
  || { echo "ERROR: cannot create work/findings dirs"; exit 6; }

# Deterministic output file names (optionally date-suffixed for local re-runs)
DATE_SUFFIX=""
if [ "$ADD_DATE" = true ] && ! test_is_remote_ops; then
    DATE_SUFFIX="_$(date -u +%Y%m%dT%H%M%SZ)"
fi
INV="${OUT_DIR}Bumblebee_Inventory${DATE_SUFFIX}.jsonl"
MERGED="${OUT_DIR}Bumblebee_Findings${DATE_SUFFIX}.jsonl"
SUMMARY_CSV="${OUT_DIR}Bumblebee_Summary${DATE_SUFFIX}.csv"
ENDPOINT_JSON="${OUT_DIR}Bumblebee_Endpoint${DATE_SUFFIX}.json"
RUN_LOG="${OUT_DIR}Bumblebee_Run${DATE_SUFFIX}.log"
: > "$RUN_LOG" 2>/dev/null || true

write_log() {
    local msg="$1"; local level="${2:-INFO}"
    local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local line="[$ts] [$level] $msg"
    echo "$line" >&2
    [ -n "$RUN_LOG" ] && echo "$line" >> "$RUN_LOG" 2>/dev/null || true
}

# Minimal JSON string escape (handles \\ and ")
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# Build the suffix injected into every emitted JSON line for SDL enrichment.
# Format: ,"RecordType":"...","hostname":"...",...   (no leading {, no trailing })
ENRICH_BASE=",\"hostname\":\"$(json_escape "$HOSTNAME_VAL")\""
ENRICH_BASE="$ENRICH_BASE,\"os_id\":\"$(json_escape "$OS_ID")\""
ENRICH_BASE="$ENRICH_BASE,\"os_version\":\"$(json_escape "$OS_VERSION")\""
ENRICH_BASE="$ENRICH_BASE,\"os_build\":\"$(json_escape "$OS_BUILD")\""
ENRICH_BASE="$ENRICH_BASE,\"os_arch\":\"$(json_escape "$OS_ARCH")\""
ENRICH_BASE="$ENRICH_BASE,\"collection_utc\":\"$COLLECTION_UTC\""
ENRICH_BASE="$ENRICH_BASE,\"tool\":\"bumblebee\""

# Endpoint metadata record (single JSON object, .json so SDL parses cleanly)
cat > "$ENDPOINT_JSON" <<EOF
{
  "RecordType": "BumblebeeEndpointInfo",
  "hostname": "$(json_escape "$HOSTNAME_VAL")",
  "os_id": "$(json_escape "$OS_ID")",
  "os_version": "$(json_escape "$OS_VERSION")",
  "os_build": "$(json_escape "$OS_BUILD")",
  "os_arch": "$(json_escape "$OS_ARCH")",
  "collection_utc": "$COLLECTION_UTC",
  "tool": "bumblebee",
  "context": "$( test_is_remote_ops && echo remoteops || echo interactive )"
}
EOF

write_log "Output dir: $OUT_DIR"
write_log "Inventory: $INV"
write_log "Findings: $MERGED"
write_log "Summary CSV: $SUMMARY_CSV"
write_log "Endpoint: $ENDPOINT_JSON"
write_log "Run log: $RUN_LOG"
write_log "Dataset: $datasetFilePath"

# ---------- config ----------
ROOTS=(/home /root /opt /usr/local /srv /var/lib)
MAX_DURATION="${MAX_DURATION:-30m}"
GH_API="https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel?ref=main"

# ---------- sanity ----------
# Expand PATH for common user/install locations
export PATH="$PATH:/usr/local/bin:/usr/local/sbin:/opt/bumblebee/bin:$HOME/.local/bin:$HOME/bin:$HOME/go/bin"

# Resolve a candidate path to an actual executable bumblebee binary.
# Accepts file or directory; if directory, probes common sub-paths.
resolveBin() {
    local p="$1"
    [ -z "$p" ] && return 1
    if [ -f "$p" ] && [ -x "$p" ]; then
        printf '%s\n' "$p"; return 0
    fi
    if [ -d "$p" ]; then
        local sub
        for sub in bumblebee bin/bumblebee dist/bumblebee build/bumblebee \
                   target/release/bumblebee target/debug/bumblebee \
                   cmd/bumblebee/bumblebee; do
            if [ -f "$p/$sub" ] && [ -x "$p/$sub" ]; then
                printf '%s\n' "$p/$sub"; return 0
            fi
        done
        # Fall back: first executable named bumblebee under that dir
        local found
        found="$(find "$p" -maxdepth 4 -type f -name bumblebee -perm -u+x 2>/dev/null | head -n1)"
        [ -n "$found" ] && { printf '%s\n' "$found"; return 0; }
    fi
    return 1
}

# Find bumblebee binary
BUMBLEBEE_BIN=""
if [ -n "${BUMBLEBEE_BIN_OVERRIDE:-}" ]; then
    BUMBLEBEE_BIN="$(resolveBin "$BUMBLEBEE_BIN_OVERRIDE" || true)"
fi
if [ -z "$BUMBLEBEE_BIN" ]; then
    inpath="$(command -v bumblebee 2>/dev/null || true)"
    [ -n "$inpath" ] && BUMBLEBEE_BIN="$(resolveBin "$inpath" || true)"
fi
if [ -z "$BUMBLEBEE_BIN" ]; then
    for cand in /usr/local/bin/bumblebee /opt/bumblebee /opt/bumblebee/bin/bumblebee \
                "$HOME/.local/bin/bumblebee" "$HOME/bin/bumblebee" \
                "$HOME/go/bin/bumblebee" "$HOME/bumblebee"; do
        BUMBLEBEE_BIN="$(resolveBin "$cand" || true)"
        [ -n "$BUMBLEBEE_BIN" ] && break
    done
fi
if [ -z "$BUMBLEBEE_BIN" ]; then
    found="$(find / -maxdepth 6 -type f -name bumblebee -perm -u+x 2>/dev/null | head -n1)"
    [ -n "$found" ] && BUMBLEBEE_BIN="$found"
fi

# If still no binary, look for a Go source tree and build it.
buildFromSource() {
    local src=""
    for cand in "${BUMBLEBEE_SRC_DIR:-}" "$HOME/bumblebee" "$HOME/src/bumblebee" \
                /opt/bumblebee /usr/local/src/bumblebee; do
        [ -z "$cand" ] && continue
        if [ -f "$cand/go.mod" ] && [ -d "$cand/cmd" ]; then
            src="$cand"; break
        fi
    done
    [ -z "$src" ] && return 1
    echo "Found bumblebee source at: $src"
    if ! command -v go >/dev/null 2>&1; then
        echo "ERROR: 'go' not in PATH; cannot build from source"
        echo "Install Go (e.g. 'sudo dnf install -y golang') or provide a prebuilt binary"
        return 1
    fi
    echo "Building bumblebee from source (go build)..."
    local outbin="$src/bumblebee"
    ( cd "$src" && GOFLAGS="-trimpath" go build -o "$outbin" ./cmd/bumblebee ) \
        || { echo "ERROR: go build failed"; return 1; }
    [ -x "$outbin" ] || { echo "ERROR: built binary missing: $outbin"; return 1; }
    BUMBLEBEE_BIN="$outbin"
    echo "Built: $BUMBLEBEE_BIN"
    return 0
}

if [ -z "$BUMBLEBEE_BIN" ] || [ ! -x "$BUMBLEBEE_BIN" ]; then
    buildFromSource || true
fi

if [ -z "$BUMBLEBEE_BIN" ] || [ ! -x "$BUMBLEBEE_BIN" ]; then
    echo "ERROR: bumblebee executable not found and could not be built"
    echo "PATH=$PATH"
    echo "Options:"
    echo "  - install Go and retry (script will build from \$HOME/bumblebee)"
    echo "  - set BUMBLEBEE_SRC_DIR=/path/to/source and retry"
    echo "  - set BUMBLEBEE_BIN_OVERRIDE=/full/path/to/bumblebee and retry"
    exit 127
fi
echo "bumblebee binary: $BUMBLEBEE_BIN"

command -v curl >/dev/null 2>&1 || { echo "ERROR: curl missing"; exit 127; }
"$BUMBLEBEE_BIN" --version || true
"$BUMBLEBEE_BIN" selftest || echo "WARN: selftest reported issues, continuing"

# ---------- build root args ----------
ROOT_ARGS=()
for r in "${ROOTS[@]}"; do
  if [ -d "$r" ] && [ -r "$r" ]; then
    ROOT_ARGS+=(--root "$r"); echo "root+ $r"
  else
    echo "root- $r (missing/unreadable, skipped)"
  fi
done
[ "${#ROOT_ARGS[@]}" -eq 0 ] && { echo "ERROR: no readable roots"; exit 2; }

# ---------- fetch ALL exposure catalogs ----------
echo "Fetching exposure catalog list from $GH_API"
CATALOG_LIST="$WORK_DIR/catalog_list.json"
curl -fsSL -H "Accept: application/vnd.github+json" "$GH_API" -o "$CATALOG_LIST" \
  || { echo "ERROR: cannot list threat_intel/"; exit 3; }

mapfile -t URLS < <(grep -Eo '"download_url":[[:space:]]*"[^"]+\.json"' "$CATALOG_LIST" \
                    | sed -E 's/.*"(https:[^"]+)".*/\1/')
echo "Found ${#URLS[@]} exposure catalogs"
[ "${#URLS[@]}" -eq 0 ] && { echo "ERROR: no catalogs found"; exit 4; }

for u in "${URLS[@]}"; do
  fn="$CATALOG_DIR/$(basename "$u")"
  curl -fsSL "$u" -o "$fn" && echo "got $(basename "$fn")" \
    || echo "WARN: failed to fetch $u"
done

# ---------- 1) deep baseline inventory ----------
write_log "Starting deep baseline inventory"
INV_RAW="$WORK_DIR/inventory.raw.jsonl"
"$BUMBLEBEE_BIN" scan \
  --profile deep \
  "${ROOT_ARGS[@]}" \
  --max-duration "$MAX_DURATION" \
  > "$INV_RAW" 2> "${OUT_DIR}Bumblebee_Inventory${DATE_SUFFIX}.stderr.log"

# Enrich every inventory line: prepend RecordType + endpoint metadata
awk -v suffix="\"RecordType\":\"BumblebeeInventory\"${ENRICH_BASE}," '
  /^[[:space:]]*\{/ { sub(/\{/, "{" suffix); print; next }
  { print }
' "$INV_RAW" > "$INV"
INV_LINES=$(wc -l < "$INV" 2>/dev/null | tr -d ' ')
write_log "inventory_lines=$INV_LINES"

# ---------- 2) per-catalog exposure scans (findings-only) ----------
write_log "Starting per-catalog exposure scans"
echo "RecordType,catalog,findings,exit_code,hostname,collection_utc" > "$SUMMARY_CSV"
: > "$MERGED"

shopt -s nullglob
for cat in "$CATALOG_DIR"/*.json; do
  name="$(basename "$cat" .json)"
  out_raw="$WORK_DIR/${name}.raw.jsonl"
  out="${FINDINGS_DIR}/Bumblebee_Findings_${name}${DATE_SUFFIX}.jsonl"
  err="${FINDINGS_DIR}/Bumblebee_Findings_${name}${DATE_SUFFIX}.stderr.log"
  write_log "Scanning catalog: $name"
  "$BUMBLEBEE_BIN" scan \
    --profile deep \
    "${ROOT_ARGS[@]}" \
    --exposure-catalog "$cat" \
    --findings-only \
    --max-duration "$MAX_DURATION" \
    > "$out_raw" 2> "$err"
  rc=$?
  # Enrich every emitted line with RecordType + catalog + endpoint metadata
  awk -v c="$name" -v base="$ENRICH_BASE" '
    BEGIN { suffix = "\"RecordType\":\"BumblebeeFinding\",\"catalog\":\"" c "\"" base "," }
    /^[[:space:]]*\{/ { sub(/\{/, "{" suffix); print; next }
    { print }
  ' "$out_raw" > "$out"
  lines=$(wc -l < "$out" 2>/dev/null | tr -d ' ')
  printf 'BumblebeeFindingSummary,%s,%s,%s,%s,%s\n' \
    "$name" "$lines" "$rc" "$HOSTNAME_VAL" "$COLLECTION_UTC" >> "$SUMMARY_CSV"
  cat "$out" >> "$MERGED"
  write_log "  findings=$lines rc=$rc"
done

# ---------- dataset.json run summary (XDR ingestion) ----------
TOTAL=$(awk -F, 'NR>1{s+=$3} END{print s+0}' "$SUMMARY_CSV")
END_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$datasetFilePath" <<EOF
{
  "RecordType": "BumblebeeScanSummary",
  "tool": "bumblebee",
  "profile": "deep",
  "hostname": "$(json_escape "$HOSTNAME_VAL")",
  "os_id": "$(json_escape "$OS_ID")",
  "os_version": "$(json_escape "$OS_VERSION")",
  "os_build": "$(json_escape "$OS_BUILD")",
  "os_arch": "$(json_escape "$OS_ARCH")",
  "started_utc": "$START_UTC",
  "end_utc": "$END_UTC",
  "catalogs_scanned": ${#URLS[@]},
  "total_findings": ${TOTAL},
  "inventory_lines": ${INV_LINES:-0},
  "output_dir": "$(json_escape "$OUT_DIR")",
  "endpoint_file": "$(json_escape "$ENDPOINT_JSON")",
  "inventory_file": "$(json_escape "$INV")",
  "findings_file": "$(json_escape "$MERGED")",
  "summary_csv": "$(json_escape "$SUMMARY_CSV")",
  "run_log": "$(json_escape "$RUN_LOG")"
}
EOF

# ---------- summary ----------
echo "===== SUMMARY ====="
cat "$SUMMARY_CSV"
echo "total_findings=$TOTAL"
echo "inventory_lines=${INV_LINES:-0}"
echo "output_dir=$OUT_DIR"
echo "end_utc=$END_UTC"
write_log "Run complete: total_findings=$TOTAL inventory_lines=${INV_LINES:-0}" SUCCESS

# STDOUT JSON summary line — always collected by the Agent and ingested as a
# single event in Singularity Data Lake even if file collection is not
# configured to pick up the .jsonl/.csv outputs.
printf '{"RecordType":"BumblebeeScanSummary","hostname":"%s","profile":"deep","catalogs_scanned":%d,"total_findings":%d,"inventory_lines":%d,"output_dir":"%s","dataset_file":"%s","started_utc":"%s","end_utc":"%s"}\n' \
    "$(json_escape "$HOSTNAME_VAL")" "${#URLS[@]}" "$TOTAL" "${INV_LINES:-0}" \
    "$(json_escape "$OUT_DIR")" "$(json_escape "$datasetFilePath")" \
    "$START_UTC" "$END_UTC"

rm -rf "$WORK_DIR"
exit 0
