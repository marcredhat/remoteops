#!/usr/bin/env python3
"""Walk Chrome/Edge/Brave Extensions dirs, read manifest.json, ship to SDL."""
import glob, json, os, socket, sys, time, urllib.request, uuid, getpass

SDL_URL   = os.environ.get("SDL_XDR_URL", "https://xdr.us1.sentinelone.net") + "/api/addEvents"
SDL_TOKEN = os.environ["SDL_LOG_WRITE_KEY"]

HOST = socket.getfqdn() or socket.gethostname()
USER = getpass.getuser()
HOME = os.path.expanduser("~")

# macOS + Linux common roots; pattern matches: <root>/<profile>/Extensions/<extid>/<ver>/manifest.json
roots = [
    f"{HOME}/Library/Application Support/Google/Chrome",
    f"{HOME}/Library/Application Support/Microsoft Edge",
    f"{HOME}/Library/Application Support/BraveSoftware/Brave-Browser",
    f"{HOME}/Library/Application Support/Chromium",
    f"{HOME}/.config/google-chrome",
    f"{HOME}/.config/microsoft-edge",
    f"{HOME}/.config/BraveSoftware/Brave-Browser",
    f"{HOME}/.config/chromium",
]

manifests = []
for root in roots:
    for m in glob.glob(f"{root}/*/Extensions/*/*/manifest.json"):
        try:
            size = os.path.getsize(m)
            if size > 512 * 1024:           # skip absurdly large manifests
                continue
            with open(m, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            # extract ext_id (32-char a-p) from path
            parts = m.split("/Extensions/")
            ext_id = parts[1].split("/")[0] if len(parts) > 1 else ""
            # also pull a parsed perms list when possible
            perms, host_perms, name, version = [], [], "", ""
            try:
                j = json.loads(raw)
                perms = j.get("permissions", []) or []
                host_perms = j.get("host_permissions", []) or []
                name = j.get("name", "") or ""
                version = j.get("version", "") or ""
            except Exception:
                pass
            manifests.append({
                "file.path": m,
                "file.content": raw,
                "file.size": size,
                "ext_id": ext_id,
                "ext.name": name,
                "ext.version": version,
                "ext.permissions": ",".join(perms),
                "ext.host_permissions": ",".join(host_perms),
            })
        except Exception as e:
            print(f"skip {m}: {e}", file=sys.stderr)

print(f"found {len(manifests)} manifest.json files", file=sys.stderr)
if not manifests:
    sys.exit(0)

ts_ns = str(time.time_ns())
events = []
for i, m in enumerate(manifests):
    attrs = {
        "serverHost": HOST,
        "endpoint.name": HOST,
        "actor.user.name": USER,
        "dataSource": "browser-extension-audit",
        "dataSource.name": "browser-extension-audit",
    }
    attrs.update(m)
    # nanosecond timestamps strictly monotonic
    events.append({"ts": str(int(ts_ns) + i), "attrs": attrs})

body = json.dumps({
    "session": str(uuid.uuid4()),
    "sessionInfo": {
        "serverHost": HOST,
        "logfile": "chrome-extensions",
        "parser": "json",
    },
    "events": events,
}).encode()

req = urllib.request.Request(
    SDL_URL, data=body, method="POST",
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SDL_TOKEN}",
    },
)
with urllib.request.urlopen(req, timeout=30) as resp:
    print("HTTP", resp.status)
    print(resp.read().decode())
