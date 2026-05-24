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
setResultOutputDir() {
    resultOutputDir="/opt/sentinelone/rso/"
    if [ -n "${S1_OUTPUT_DIR_PATH:-}" ]; then
        resultOutputDir="$S1_OUTPUT_DIR_PATH"
    fi
    case "$resultOutputDir" in
        */) : ;;
        *)  resultOutputDir="${resultOutputDir}/" ;;
    esac
    if ! mkdir -p "$resultOutputDir" 2>/dev/null; then
        resultOutputDir="$(pwd)/"
        echo "WARN: falling back to cwd for outputs"
    fi
    echo "Script output directory is: $resultOutputDir"
}

setDataSetFilePath() {
    datasetFilePath="${resultOutputDir}dataset.json"
    if [ -n "${S1_XDR_OUTPUT_FILE_PATH:-}" ]; then
        datasetFilePath="$S1_XDR_OUTPUT_FILE_PATH"
    fi
    mkdir -p "$(dirname "$datasetFilePath")" 2>/dev/null || true
    echo "XDR json output file path: $datasetFilePath"
}

setResultOutputDir
setDataSetFilePath

OUT_DIR="$resultOutputDir"
WORK_DIR="$(mktemp -d -t bumblebee-XXXXXX)"
CATALOG_DIR="$WORK_DIR/threat_intel"
FINDINGS_DIR="${OUT_DIR}findings"
mkdir -p "$CATALOG_DIR" "$FINDINGS_DIR"

# ---------- config ----------
ROOTS=(/home /root /opt /usr/local /srv /var/lib)
MAX_DURATION="${MAX_DURATION:-30m}"
GH_API="https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel?ref=main"

# ---------- sanity ----------
command -v bumblebee >/dev/null 2>&1 || { echo "ERROR: bumblebee not in PATH"; exit 127; }
command -v curl      >/dev/null 2>&1 || { echo "ERROR: curl missing";      exit 127; }
bumblebee --version || true
bumblebee self-test || echo "WARN: self-test reported issues, continuing"

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
bumblebee scan \
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
  bumblebee scan \
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
