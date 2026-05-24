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

echo "===== RemoteOps: bumblebee deep exposure scan ====="
uname -a
id
date -u +"start_utc=%Y-%m-%dT%H:%M:%SZ"

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
"$BUMBLEBEE_BIN" self-test || echo "WARN: self-test reported issues, continuing"

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
echo "----- deep baseline inventory -----"
INV="${OUT_DIR}inventory.jsonl"
"$BUMBLEBEE_BIN" scan \
  --profile deep \
  "${ROOT_ARGS[@]}" \
  --max-duration "$MAX_DURATION" \
  > "$INV" 2> "${OUT_DIR}inventory.stderr.log"
echo "inventory_lines=$(wc -l < "$INV")"

# ---------- 2) per-catalog exposure scans (findings-only) ----------
echo "----- per-catalog exposure scans -----"
SUMMARY_CSV="${OUT_DIR}findings_summary.csv"
echo "catalog,findings,exit_code" > "$SUMMARY_CSV"

MERGED="${OUT_DIR}findings_all.jsonl"
: > "$MERGED"

shopt -s nullglob
for cat in "$CATALOG_DIR"/*.json; do
  name="$(basename "$cat" .json)"
  out="${FINDINGS_DIR}/${name}.jsonl"
  err="${FINDINGS_DIR}/${name}.stderr.log"
  echo ">> scanning catalog: $name"
  "$BUMBLEBEE_BIN" scan \
    --profile deep \
    "${ROOT_ARGS[@]}" \
    --exposure-catalog "$cat" \
    --findings-only \
    --max-duration "$MAX_DURATION" \
    > "$out" 2> "$err"
  rc=$?
  lines=$(wc -l < "$out" 2>/dev/null || echo 0)
  echo "${name},${lines},${rc}" >> "$SUMMARY_CSV"
  awk -v c="$name" '{ sub(/}[[:space:]]*$/, ",\"catalog\":\""c"\"}"); print }' "$out" >> "$MERGED"
  echo "   findings=$lines rc=$rc"
done

# ---------- dataset.json summary (XDR ingestion) ----------
TOTAL=$(awk -F, 'NR>1{s+=$2} END{print s+0}' "$SUMMARY_CSV")
cat > "$datasetFilePath" <<EOF
{
  "tool": "bumblebee",
  "profile": "deep",
  "host": "$(hostname)",
  "started_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "catalogs_scanned": ${#URLS[@]},
  "total_findings": ${TOTAL},
  "output_dir": "${OUT_DIR}",
  "inventory_file": "${INV}",
  "findings_file": "${MERGED}",
  "summary_csv": "${SUMMARY_CSV}"
}
EOF

# ---------- summary ----------
echo "===== SUMMARY ====="
cat "$SUMMARY_CSV"
echo "total_findings=$TOTAL"
echo "output_dir=$OUT_DIR"
date -u +"end_utc=%Y-%m-%dT%H:%M:%SZ"

rm -rf "$WORK_DIR"
exit 0
