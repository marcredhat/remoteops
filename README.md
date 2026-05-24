# remoteops

SentinelOne RemoteOps scripts.

## Scripts

### `bumblebee_deep_scan.sh`

Deep supply-chain exposure scan for RHEL 10 (and other Linux) endpoints using
[`perplexityai/bumblebee`](https://github.com/perplexityai/bumblebee).

- Runs `bumblebee scan --profile deep` against system-wide roots
  (`/home`, `/root`, `/opt`, `/usr/local`, `/srv`, `/var/lib`).
- Downloads **every** exposure catalog from
  [`bumblebee/threat_intel`](https://github.com/perplexityai/bumblebee/tree/main/threat_intel)
  and scans them **one at a time** (catalogs can differ in `schema_version`,
  which would break a single `--exposure-catalog <dir>` merge).
- Writes outputs to `$S1_OUTPUT_DIR_PATH` (Agent-provided) with fallback to
  `/opt/sentinelone/rso/` and finally the script's CWD.
- Uses `.jsonl` / `.csv` / `.json` extensions so RemoteOps forwards data to
  Singularity Data Lake natively.
- Honors `$S1_XDR_OUTPUT_FILE_PATH` for the `dataset.json` summary.

Outputs:

| File | `RecordType` | Purpose |
| --- | --- | --- |
| `Bumblebee_Endpoint.json` | `BumblebeeEndpointInfo` | Host/OS metadata for the run |
| `Bumblebee_Inventory.jsonl` | `BumblebeeInventory` | Deep baseline package/extension inventory (each line enriched with hostname/OS) |
| `findings/Bumblebee_Findings_<catalog>.jsonl` | `BumblebeeFinding` | Per-catalog findings |
| `Bumblebee_Findings.jsonl` | `BumblebeeFinding` | Merged findings across all catalogs |
| `Bumblebee_Summary.csv` | `BumblebeeFindingSummary` | Per-catalog counts + hostname + collection time |
| `Bumblebee_Run.json` (or `$S1_XDR_OUTPUT_FILE_PATH`) | `BumblebeeScanSummary` | Run-level XDR summary |
| `Bumblebee_Run.log` | (text) | Per-step run log, one event per line |

Every emitted JSON line carries `RecordType`, `hostname`, `os_id`, `os_version`,
`os_build`, `os_arch`, `collection_utc`, `tool`, so SDL queries can filter by
`RecordType='BumblebeeFinding'` without needing to join against the endpoint
record.

Local CLI flag:

- `--add-date` — append a UTC timestamp to output file names (ignored under
  RemoteOps to keep names deterministic for collection).

A final **STDOUT JSON line** (`{"RecordType":"BumblebeeScanSummary",...}`) is
also emitted. STDOUT is always collected by newer Agents, so this guarantees a
queryable summary in Singularity Data Lake even when file collection is not
configured for `$S1_OUTPUT_DIR_PATH`.

### Ingestion notes (AI SIEM / Singularity Data Lake)

- Files with `.json`, `.jsonl`, `.csv` extensions in `$S1_OUTPUT_DIR_PATH` are
  parsed cleanly by the Agent and forwarded as structured events.
- Other extensions (e.g. `.log`) are treated as text — one line per event.
- If you want files written outside `$S1_OUTPUT_DIR_PATH` to be ingested, use
  RemoteOps **"Specify paths to collect results from"** and list the absolute
  paths.
- Sending to AI SIEM also requires the appropriate **Data ingest + retention
  SKU** and a **Data Export Profile** pointing to Singularity Data Lake.

Env overrides:

- `S1_OUTPUT_DIR_PATH` — RemoteOps output dir (preferred).
- `S1_XDR_OUTPUT_FILE_PATH` — Override path for `dataset.json`.
- `MAX_DURATION` — Per-scan timeout, default `30m`.
- `BUMBLEBEE_BIN_OVERRIDE` — Force a specific bumblebee binary path.
- `BUMBLEBEE_SRC_DIR` — Bumblebee source directory (for auto-build fallback).

### Endpoint provisioning (RemoteOps)

The Agent runs scripts as **root** with a minimal environment. Install the
bumblebee binary system-wide on each endpoint once, so the scan script just
picks it up from `PATH`:

```bash
# One-shot, runs as root, builds from upstream and installs to /usr/local/bin
curl -fsSL https://raw.githubusercontent.com/marcredhat/remoteops/main/install_bumblebee.sh \
  | sudo bash
```

Or with explicit control:

```bash
sudo BUMBLEBEE_REF=main ./install_bumblebee.sh
sudo BUMBLEBEE_SRC_DIR=/opt/bumblebee ./install_bumblebee.sh   # use existing source
sudo DEST=/usr/local/bin/bumblebee ./install_bumblebee.sh      # custom destination
```

After install, `bumblebee_deep_scan.sh` will find the binary on `PATH` and skip
the build step — suitable for restricted RemoteOps execution where outbound
package installs are not desirable at scan time.
