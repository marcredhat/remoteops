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

| File | Purpose |
| --- | --- |
| `inventory.jsonl` | Deep baseline package/extension inventory |
| `findings/<catalog>.jsonl` | Per-catalog findings (findings-only mode) |
| `findings_all.jsonl` | Merged findings, each line tagged with `catalog` |
| `findings_summary.csv` | `catalog,findings,exit_code` summary |
| `dataset.json` | Run-level XDR summary |

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
