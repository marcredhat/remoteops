# Bumblebee Exposure Dashboard (SDL)

Tabbed Singularity Data Lake dashboard that visualises both **real**
findings (from `bumblebee_deep_scan.sh` RemoteOps runs) and **simulated**
exposure built from the public
[`perplexityai/bumblebee/threat_intel`](https://github.com/perplexityai/bumblebee/tree/main/threat_intel)
catalogs (654 entries across 8 catalogs).

Authored following the
[`pmoses-s1/claude-skills`](https://github.com/pmoses-s1/claude-skills)
`sentinelone-sdl-dashboard` skill conventions (explicit `x/y/w/h` layout on
the 60-wide grid, safe PowerQuery patterns, markdown body field, etc.).

## Files

| File | Purpose |
| --- | --- |
| `bumblebee_dashboard.json` | Tabbed SDL dashboard JSON (5 tabs) |
| `generate_simulated_exposure.py` | Builds JSONL from the public catalogs |
| `ingest_to_sdl.sh` | Uploads JSONL to SDL via `uploadLogs` |
| `deploy_dashboard.sh` | `putFile`s the dashboard JSON into `/dashboards/...` |

## Tabs

| Tab | Source `RecordType` | What it shows |
| --- | --- | --- |
| Overview | both | Side-by-side real vs simulated counts |
| Real findings | `BumblebeeFinding` | Counts, by host, by catalog, detail table |
| Simulated exposure | `BumblebeeSimulatedExposure` | Catalog coverage, severity/ecosystem mix |
| Run summary | `BumblebeeScanSummary` | Last scan per host (real runs) |
| Reference | — | Catalog descriptions + refresh procedure |

## End-to-end deploy

```bash
# 1. Generate the simulated stream from the public catalogs
python3 generate_simulated_exposure.py --out simulated_exposure.jsonl

# 2. Ingest it into SDL (need SDL Log Write key)
SDL_TOKEN=xxxxx SDL_SOURCE=bumblebee-simulated \
  ./ingest_to_sdl.sh simulated_exposure.jsonl

# 3. Deploy the dashboard (need SDL Config Write key)
SDL_TOKEN=yyyyy ./deploy_dashboard.sh

# 4. Trigger a real RemoteOps run of bumblebee_deep_scan.sh on a fleet sample
#    (see the parent README) — its enriched JSONL output will populate the
#    "Real findings" and "Run summary" tabs.
```

## Quick verification queries

```
RecordType='BumblebeeFinding' or RecordType='BumblebeeSimulatedExposure' or RecordType='BumblebeeScanSummary'
| group c=count() by RecordType
| sort -c
```

```
RecordType='BumblebeeSimulatedExposure'
| group c=count() by catalog, severity
| sort catalog, -c
```

```
RecordType='BumblebeeFinding'
| group c=count() by hostname, catalog
| sort -c
```

## Notes on the dashboard JSON

- `configType: "TABBED"` with per-tab `filters[]` for live `hostname`/`catalog`/`ecosystem`/`severity` faceting.
- Number panels all end with `| limit 1` per the skill's pre-deploy safety rules.
- `donut` panels return exactly one text + one numeric column.
- `stacked_bar` with `xAxis: "grouped_data"` uses `| transpose` only on
  hyphen-free dimensions (`severity`, `catalog` after value coercion if
  needed).
- Markdown panels use the `markdown:` body field (NOT `content:`), and the
  `title` field is never duplicated inside the markdown body.
- A panel that returns 0 on the **Real findings** tab is the **expected
  SOC-positive posture** — flagged explicitly in the tab intro markdown.
