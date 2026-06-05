# browser-extension-audit

Lightweight collector that walks Chromium-family browser profiles (Chrome, Edge,
Brave, Chromium) on macOS / Linux, reads every installed extension's
`manifest.json`, and ships the body + parsed permissions to a SentinelOne
Singularity Data Lake (SDL) tenant via the `addEvents` API.

Once ingested, you can hunt high-risk permission sets in Event Search / Purple AI
SIEM without needing DLP-style file capture from the EDR agent.

## What it sends

For every `*/Extensions/<ext_id>/<version>/manifest.json` it finds, one event
with these fields:

| field                | example                                                       |
|----------------------|---------------------------------------------------------------|
| `serverHost`         | `marc-mbp.local`                                              |
| `endpoint.name`      | `marc-mbp.local`                                              |
| `actor.user.name`    | `marc.chisinevski`                                            |
| `dataSource.name`    | `browser-extension-audit`                                     |
| `file.path`          | `/Users/…/Chrome/Default/Extensions/<extid>/1.2.3/manifest.json` |
| `file.content`       | raw manifest JSON text                                        |
| `file.size`          | bytes                                                         |
| `ext_id`             | 32-char `a-p` extension id                                    |
| `ext.name`           | extension name from manifest                                  |
| `ext.version`        | extension version                                             |
| `ext.permissions`    | comma-joined `permissions` array                              |
| `ext.host_permissions` | comma-joined `host_permissions` array                       |

Manifests larger than 512 KB are skipped to keep events well under the SDL row
size limit.

## Usage

Set two env vars and run:

```bash
export SDL_XDR_URL='https://xdr.us1.sentinelone.net'   # or eu1 / ap1
export SDL_LOG_WRITE_KEY='<SDL Log Write JWT>'        # from SDL → Settings → API Keys
python3 collect_ext_manifests.py
```

No third-party packages required — uses only the Python 3 standard library.

The script prints how many manifests it found and the HTTP response from
`/api/addEvents` (expect `HTTP 200` + `{"status":"success"}`).

## Hunting queries

After ingest (~30–60 s for indexing) run these in Event Search.

### High-risk permissions (uses the pre-parsed fields, cheap)

```text
dataSource.name = 'browser-extension-audit'
| filter ext.permissions contains ('webRequestBlocking','cookies','declarativeNetRequest','scripting')
       or ext.host_permissions contains ('<all_urls>')
| group n = count(),
        endpoints = estimate_distinct(endpoint.name),
        users     = estimate_distinct(actor.user.name)
        by serverHost, ext_id, ext.name, ext.version
| sort -n
```

### Full-text scan over the raw manifest body

```text
dataSource.name = 'browser-extension-audit'
| filter file.path matches ".*/Extensions/[a-p]{32}/.*/manifest\\.json$"
| filter file.content contains ('<all_urls>','webRequestBlocking','cookies','declarativeNetRequest','scripting')
| parse "/Extensions/$ext_id_p{regex=[a-p]{32}}$/" from file.path
| group n = count(),
        endpoints = estimate_distinct(endpoint.name),
        users     = estimate_distinct(actor.user.name)
        by serverHost, ext_id
| sort -n
```

## Fleet deployment

The script is single-file, stdlib-only, and exits 0 on success — easy to wrap in:

- **S1 RemoteOps** task (script library) on a daily schedule
- **Ansible / Jamf / Intune / MDM** push
- **Hyperautomation** workflow

A Windows PowerShell port is on the TODO list — the logic is identical, only
the profile-root paths change (`%LOCALAPPDATA%\Google\Chrome\User Data\…`).

## Safety / privacy notes

- Only reads `manifest.json` (extension metadata) — never the user's browsing
  data, cookies, or extension storage.
- Skips files >512 KB.
- All secrets are env-var driven; nothing is logged or committed.
