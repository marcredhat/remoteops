#!/usr/bin/env python3
"""Generate simulated BumblebeeSimulatedExposure events from the public
perplexityai/bumblebee/threat_intel exposure catalogs.

One event per (catalog, ecosystem, package, version) tuple, randomly
distributed across a synthetic host pool so that fleet-level visualisations
(by host, by catalog, by severity) have data even before any agent scan.

Usage:
    python3 generate_simulated_exposure.py --out simulated_exposure.jsonl
    python3 generate_simulated_exposure.py --hosts 25 --out events.jsonl

The output is newline-delimited JSON (JSONL) ready for SDL `uploadLogs`
ingestion via `ingest_to_sdl.sh`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import sys
import urllib.request

GH_API = (
    "https://api.github.com/repos/perplexityai/bumblebee/"
    "contents/threat_intel?ref=main"
)


def fetch_catalogs(work_dir: str) -> list[str]:
    """Return list of local catalog paths, downloading on demand."""
    os.makedirs(work_dir, exist_ok=True)
    listing_path = os.path.join(work_dir, "_list.json")
    with urllib.request.urlopen(GH_API, timeout=30) as r:
        listing = json.load(r)
    with open(listing_path, "w") as f:
        json.dump(listing, f)

    paths = []
    for item in listing:
        if item.get("type") != "file" or not item.get("name", "").endswith(".json"):
            continue
        name = item["name"]
        url = item.get("download_url")
        if not url:
            continue
        local = os.path.join(work_dir, name)
        if not os.path.exists(local):
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
            with open(local, "wb") as f:
                f.write(data)
        paths.append(local)
    return sorted(paths)


def stable_host(seed: str, host_pool: list[str]) -> str:
    """Deterministically assign a host to a package/version pair."""
    h = hashlib.sha1(seed.encode()).digest()
    idx = int.from_bytes(h[:4], "big") % len(host_pool)
    return host_pool[idx]


def generate(catalog_paths: list[str], host_pool: list[str], now_iso: str):
    for path in catalog_paths:
        catalog_name = os.path.basename(path).replace(".json", "")
        with open(path) as f:
            data = json.load(f)
        for entry in data.get("entries", []) or []:
            ecosystem = (entry.get("ecosystem") or "unknown").lower()
            package = entry.get("package") or entry.get("name") or ""
            severity = (entry.get("severity") or "unknown").lower()
            entry_id = entry.get("id") or ""
            versions = entry.get("versions") or [None]
            for version in versions:
                ver_str = version if version is not None else ""
                seed = f"{catalog_name}|{ecosystem}|{package}|{ver_str}"
                host = stable_host(seed, host_pool)
                yield {
                    "RecordType": "BumblebeeSimulatedExposure",
                    "gen_v": 2,
                    "tool": "bumblebee",
                    "simulated": True,
                    "collection_utc": now_iso,
                    "hostname": host,
                    "catalog": catalog_name,
                    "ecosystem": ecosystem,
                    "package": package,
                    "pkg_version": ver_str,
                    "pkg_severity": severity,
                    "entry_id": entry_id,
                    "source": "perplexityai/bumblebee/threat_intel",
                }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--out", default="simulated_exposure.jsonl",
                   help="Output JSONL file (default: %(default)s)")
    p.add_argument("--hosts", type=int, default=12,
                   help="Number of synthetic hosts to distribute over (default: %(default)s)")
    p.add_argument("--host-prefix", default="sim-host-",
                   help="Prefix for synthetic hostnames (default: %(default)s)")
    p.add_argument("--work-dir", default="/tmp/bumblebee-catalogs",
                   help="Where to cache catalog JSON downloads")
    p.add_argument("--seed", type=int, default=42,
                   help="Random seed (only affects ordering, not host assignment)")
    args = p.parse_args()

    random.seed(args.seed)
    host_pool = [f"{args.host_prefix}{i:02d}" for i in range(1, args.hosts + 1)]
    print(f"Host pool: {host_pool}", file=sys.stderr)

    print(f"Fetching catalogs into {args.work_dir} ...", file=sys.stderr)
    catalog_paths = fetch_catalogs(args.work_dir)
    print(f"Got {len(catalog_paths)} catalogs", file=sys.stderr)

    now_iso = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    count = 0
    with open(args.out, "w") as f:
        for evt in generate(catalog_paths, host_pool, now_iso):
            f.write(json.dumps(evt, separators=(",", ":")) + "\n")
            count += 1
    print(f"Wrote {count} events to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
